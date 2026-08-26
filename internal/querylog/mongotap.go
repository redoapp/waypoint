package querylog

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"sync"
	"time"

	"github.com/redoapp/waypoint/internal/mongowire"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// maxPendingMongoCommands bounds the in-flight command map. Commands sent with
// the moreToCome flag never receive a reply, so without a bound a
// fire-and-forget writer would leak entries for the life of the connection.
const maxPendingMongoCommands = 256

type mongoPending struct {
	requestID  int32
	op         string
	collection string
	database   string

	// shape is the value-free rendering, used for the fingerprint at every
	// level. text is what actually reaches the log: the shape at
	// LevelNormalized, or the full command document at LevelFull.
	shape string
	text  string

	start time.Time
}

// MongoSession correlates client commands with backend replies for one
// MongoDB connection. Correlation is exact: the wire header carries a
// requestID and each reply names it in responseTo.
type MongoSession struct {
	emitter *Emitter
	base    Event

	mu      sync.Mutex
	pending map[int32]*mongoPending
	order   []int32 // requestIDs in arrival order, for bounded eviction
}

// NewMongoSession creates the correlation state for one connection.
func NewMongoSession(emitter *Emitter, base Event) *MongoSession {
	base.Mode = ModeMongoDB
	return &MongoSession{
		emitter: emitter,
		base:    base,
		pending: make(map[int32]*mongoPending),
	}
}

// ClientConn wraps the client side so commands are observed on their way out.
func (s *MongoSession) ClientConn(c net.Conn) net.Conn {
	return &framedConn{
		conn:       c,
		readHeader: mongoReadHeader,
		observe:    s.observeClient,
	}
}

// BackendConn wraps the backend side so replies can be matched to commands.
func (s *MongoSession) BackendConn(c net.Conn) net.Conn {
	return &framedConn{
		conn:       c,
		readHeader: mongoReadHeader,
		observe:    s.observeBackend,
	}
}

// mongoReadHeader reads a 16-byte MongoDB wire header, whose first field is
// the total message length in little-endian.
func mongoReadHeader(r io.Reader) ([]byte, int, error) {
	hdr := make([]byte, mongowire.HeaderSize)
	n, err := io.ReadFull(r, hdr)
	if err != nil {
		return hdr[:n], 0, err
	}
	length := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	if length < mongowire.HeaderSize {
		return hdr, 0, nil // malformed; caller passes it through
	}
	return hdr, int(length), nil
}

// LogCommand records a command observed outside the relay. The proxy forwards
// the client's first post-handshake command directly, before the relay starts,
// so without this that command would never be logged.
func (s *MongoSession) LogCommand(msg *mongowire.Message) {
	if msg == nil {
		return
	}
	s.recordCommand(msg.Header.RequestID, msg.Header.OpCode, msg.Body)
}

func (s *MongoSession) observeClient(msg []byte) {
	hdr, body := splitMongo(msg)
	if body == nil {
		return
	}
	s.recordCommand(hdr.RequestID, hdr.OpCode, body)
}

func (s *MongoSession) recordCommand(requestID, opCode int32, body []byte) {
	if opCode != mongowire.OpMsg {
		return
	}
	_, doc, err := mongowire.ParseOpMsgBody(body)
	if err != nil {
		return
	}

	name, err := mongowire.CommandName(doc)
	if err != nil {
		return
	}

	p := &mongoPending{
		requestID:  requestID,
		op:         name,
		collection: commandCollection(doc),
		database:   mongowire.CommandDB(doc),
		start:      time.Now(),
	}

	// The shape is always computed: it is what the fingerprint hashes, and a
	// fingerprint is part of even a metadata-level record.
	p.shape = commandShape(doc)
	switch {
	case s.base.Level >= LevelFull:
		// Full means the command exactly as the client sent it, values and
		// all — the Mongo counterpart to logging verbatim SQL.
		p.text = doc.String()
	case s.base.Level >= LevelNormalized:
		p.text = p.shape
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict the oldest un-replied command rather than grow without bound.
	for len(s.pending) >= maxPendingMongoCommands && len(s.order) > 0 {
		oldest := s.order[0]
		s.order = s.order[1:]
		if evicted, ok := s.pending[oldest]; ok {
			delete(s.pending, oldest)
			s.emitLocked(evicted, 0, 0, "")
		}
	}

	s.pending[requestID] = p
	s.order = append(s.order, requestID)
}

// LogReply records a reply the proxy read directly rather than through the
// tap. It is the counterpart to LogCommand: the first post-handshake exchange
// happens before the relay starts, so both halves have to be reported by hand.
func (s *MongoSession) LogReply(msg *mongowire.Message) {
	if msg == nil {
		return
	}
	s.completeCommand(msg.Header.ResponseTo, msg.Header.OpCode, msg.Body,
		int64(mongowire.HeaderSize+len(msg.Body)))
}

func (s *MongoSession) observeBackend(msg []byte) {
	hdr, body := splitMongo(msg)
	if body == nil {
		return
	}
	s.completeCommand(hdr.ResponseTo, hdr.OpCode, body, int64(len(msg)))
}

func (s *MongoSession) completeCommand(responseTo, opCode int32, body []byte, respBytes int64) {
	if responseTo == 0 {
		return
	}

	s.mu.Lock()
	p, ok := s.pending[responseTo]
	if ok {
		delete(s.pending, responseTo)
		s.removeOrderLocked(responseTo)
	}
	s.mu.Unlock()

	if !ok {
		return
	}

	rows, errMsg := replyStats(opCode, body)

	s.mu.Lock()
	s.emitLocked(p, rows, respBytes, errMsg)
	s.mu.Unlock()
}

func (s *MongoSession) removeOrderLocked(requestID int32) {
	for i, id := range s.order {
		if id == requestID {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

func (s *MongoSession) emitLocked(p *mongoPending, rows, respBytes int64, errMsg string) {
	if p == nil {
		return
	}
	ev := s.base
	ev.Op = p.op
	ev.Kind = mongoKind(p.op)
	ev.Collection = p.collection
	if p.database != "" {
		ev.Database = p.database
	}
	ev.Statement = p.text
	if p.shape != "" {
		sum := sha256.Sum256([]byte(p.shape))
		ev.Fingerprint = hex.EncodeToString(sum[:8])
	}
	ev.Rows = rows
	ev.RespBytes = respBytes
	ev.Duration = time.Since(p.start)
	ev.Err = errMsg
	s.emitter.Log(&ev)
}

// Close flushes commands still awaiting a reply.
func (s *MongoSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.order {
		if p, ok := s.pending[id]; ok {
			s.emitLocked(p, 0, 0, "")
		}
	}
	s.pending = make(map[int32]*mongoPending)
	s.order = nil
}

func splitMongo(msg []byte) (mongowire.Header, []byte) {
	if len(msg) < mongowire.HeaderSize {
		return mongowire.Header{}, nil
	}
	hdr := mongowire.Header{
		MessageLength: int32(binary.LittleEndian.Uint32(msg[0:4])),
		RequestID:     int32(binary.LittleEndian.Uint32(msg[4:8])),
		ResponseTo:    int32(binary.LittleEndian.Uint32(msg[8:12])),
		OpCode:        int32(binary.LittleEndian.Uint32(msg[12:16])),
	}
	return hdr, msg[mongowire.HeaderSize:]
}

// replyStats pulls the returned-document count and any error out of a reply.
func replyStats(opCode int32, body []byte) (rows int64, errMsg string) {
	if opCode != mongowire.OpMsg {
		return 0, ""
	}
	_, doc, err := mongowire.ParseOpMsgBody(body)
	if err != nil {
		return 0, ""
	}

	// Query replies carry their documents in cursor.firstBatch / nextBatch.
	if cursor, err := doc.LookupErr("cursor"); err == nil {
		if cdoc, ok := cursor.DocumentOK(); ok {
			for _, field := range []string{"firstBatch", "nextBatch"} {
				if batch, err := cdoc.LookupErr(field); err == nil {
					if arr, ok := batch.ArrayOK(); ok {
						if vals, err := arr.Values(); err == nil {
							rows = int64(len(vals))
						}
					}
				}
			}
		}
	}

	// Write replies report counts instead.
	if rows == 0 {
		for _, field := range []string{"nModified", "n"} {
			if v, err := doc.LookupErr(field); err == nil {
				if n, ok := numericValue(v); ok && n != 0 {
					rows = n
					break
				}
			}
		}
	}

	if v, err := doc.LookupErr("errmsg"); err == nil {
		if s, ok := v.StringValueOK(); ok {
			errMsg = s
		}
	}
	if errMsg == "" {
		if v, err := doc.LookupErr("ok"); err == nil {
			if n, ok := numericValue(v); ok && n == 0 {
				errMsg = "command failed"
			}
		}
	}

	return rows, errMsg
}

func numericValue(v bson.RawValue) (int64, bool) {
	switch v.Type {
	case bson.TypeInt32:
		i, ok := v.Int32OK()
		return int64(i), ok
	case bson.TypeInt64:
		i, ok := v.Int64OK()
		return i, ok
	case bson.TypeDouble:
		f, ok := v.DoubleOK()
		return int64(f), ok
	default:
		return 0, false
	}
}

// mongoKind classifies a command the way SQL statements are classified, so
// "did this user modify data" is answerable across both protocols.
func mongoKind(op string) string {
	switch op {
	case "find", "aggregate", "count", "distinct", "getMore", "explain":
		return KindRead
	case "insert", "update", "delete", "findAndModify", "findandmodify", "bulkWrite":
		return KindWrite
	case "create", "createIndexes", "drop", "dropDatabase", "dropIndexes",
		"collMod", "renameCollection", "createUser", "dropUser":
		return KindDDL
	case "grantRolesToUser", "revokeRolesFromUser", "createRole", "dropRole":
		return KindDCL
	case "commitTransaction", "abortTransaction":
		return KindTCL
	default:
		return KindUtility
	}
}
