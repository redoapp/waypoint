package querylog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/redoapp/waypoint/internal/mongowire"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// mongoMsg builds a complete OP_MSG wire message around doc.
func mongoMsg(t *testing.T, requestID, responseTo int32, doc bson.D) []byte {
	t.Helper()

	raw, err := bson.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling %v: %v", doc, err)
	}
	body := mongowire.BuildOpMsg(0, raw)

	total := mongowire.HeaderSize + len(body)
	msg := make([]byte, total)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(total))
	binary.LittleEndian.PutUint32(msg[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(mongowire.OpMsg))
	copy(msg[mongowire.HeaderSize:], body)
	return msg
}

func newMongoTestSession(t *testing.T, level Level) (*MongoSession, func() []map[string]any) {
	t.Helper()
	logger, records := captureLogger(t)
	emitter := NewEmitter(logger, 8192, Counters{})
	t.Cleanup(emitter.Close)

	s := NewMongoSession(emitter, Event{
		ConnID:   "conn1",
		Listener: "mongo-test",
		User:     "alice@example.com",
		Database: "app",
		Level:    level,
	})
	return s, func() []map[string]any {
		emitter.Close()
		return records()
	}
}

// The Mongo tap sits inside the same relay as the Postgres one, so it carries
// the same byte-transparency obligation.
func TestMongoTap_BytesPassThroughUnchanged(t *testing.T) {
	stream := bytes.Join([][]byte{
		mongoMsg(t, 1, 0, bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "id", Value: 42}}}, {Key: "$db", Value: "app"}}),
		mongoMsg(t, 2, 0, bson.D{{Key: "insert", Value: "users"}, {Key: "documents", Value: bson.A{bson.D{{Key: "name", Value: "bob"}}}}, {Key: "$db", Value: "app"}}),
	}, nil)

	for _, bufSize := range []int{1, 5, 17, 256, 4096, 65536} {
		t.Run(fmt.Sprintf("%d-byte reads", bufSize), func(t *testing.T) {
			s, _ := newMongoTestSession(t, LevelNormalized)
			tap := s.ClientConn(newFakeConn(stream))

			var got bytes.Buffer
			buf := make([]byte, bufSize)
			for {
				n, err := tap.Read(buf)
				got.Write(buf[:n])
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("read: %v", err)
				}
			}
			if !bytes.Equal(got.Bytes(), stream) {
				t.Errorf("stream corrupted with %d-byte reads", bufSize)
			}
		})
	}
}

func TestMongoTap_CorrelatesByRequestID(t *testing.T) {
	s, records := newMongoTestSession(t, LevelNormalized)

	// Two commands issued back to back, replied to out of order.
	client := s.ClientConn(newFakeConn(bytes.Join([][]byte{
		mongoMsg(t, 10, 0, bson.D{{Key: "find", Value: "orders"}, {Key: "filter", Value: bson.D{{Key: "id", Value: 42}}}, {Key: "$db", Value: "shop"}}),
		mongoMsg(t, 11, 0, bson.D{{Key: "insert", Value: "users"}, {Key: "documents", Value: bson.A{bson.D{{Key: "n", Value: "bob"}}}}, {Key: "$db", Value: "shop"}}),
	}, nil)))

	backend := s.BackendConn(newFakeConn(bytes.Join([][]byte{
		// Reply to the insert first.
		mongoMsg(t, 90, 11, bson.D{{Key: "n", Value: 1}, {Key: "ok", Value: 1.0}}),
		// Then the find, returning two documents.
		mongoMsg(t, 91, 10, bson.D{
			{Key: "cursor", Value: bson.D{
				{Key: "firstBatch", Value: bson.A{bson.D{{Key: "id", Value: 1}}, bson.D{{Key: "id", Value: 2}}}},
				{Key: "id", Value: int64(0)},
			}},
			{Key: "ok", Value: 1.0},
		}),
	}, nil)))

	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %v", len(recs), recs)
	}

	byOp := map[string]map[string]any{}
	for _, r := range recs {
		op, _ := r["op"].(string)
		byOp[op] = r
	}

	insert, ok := byOp["insert"]
	if !ok {
		t.Fatalf("no insert record: %v", recs)
	}
	if insert["collection"] != "users" {
		t.Errorf("insert collection = %v, want users", insert["collection"])
	}
	if insert["kind"] != KindWrite {
		t.Errorf("insert kind = %v, want %v", insert["kind"], KindWrite)
	}
	if insert["rows"] != float64(1) {
		t.Errorf("insert rows = %v, want 1", insert["rows"])
	}

	find, ok := byOp["find"]
	if !ok {
		t.Fatalf("no find record: %v", recs)
	}
	if find["collection"] != "orders" {
		t.Errorf("find collection = %v, want orders", find["collection"])
	}
	if find["kind"] != KindRead {
		t.Errorf("find kind = %v, want %v", find["kind"], KindRead)
	}
	if find["rows"] != float64(2) {
		t.Errorf("find rows = %v, want 2 (firstBatch length)", find["rows"])
	}
	if find["database"] != "shop" {
		t.Errorf("find database = %v, want shop (from $db)", find["database"])
	}
}

func TestMongoTap_ShapeHidesValues(t *testing.T) {
	s, records := newMongoTestSession(t, LevelNormalized)

	client := s.ClientConn(newFakeConn(mongoMsg(t, 1, 0, bson.D{
		{Key: "find", Value: "users"},
		{Key: "filter", Value: bson.D{{Key: "email", Value: "alice@example.com"}, {Key: "age", Value: 37}}},
		{Key: "$db", Value: "app"},
	})))
	backend := s.BackendConn(newFakeConn(mongoMsg(t, 2, 1, bson.D{{Key: "ok", Value: 1.0}})))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	stmt, _ := recs[0]["statement"].(string)

	if strings.Contains(stmt, "alice@example.com") || strings.Contains(stmt, "37") {
		t.Errorf("shape leaked values: %q", stmt)
	}
	// Structure is retained: the command, collection and field names.
	for _, want := range []string{"find", "users", "filter", "email", "age", "?string", "?int"} {
		if !strings.Contains(stmt, want) {
			t.Errorf("shape %q is missing %q", stmt, want)
		}
	}
	if recs[0]["fingerprint"] == nil {
		t.Error("fingerprint is missing")
	}
}

func TestMongoTap_NoStatementAtMetadataLevel(t *testing.T) {
	s, records := newMongoTestSession(t, LevelMetadata)

	client := s.ClientConn(newFakeConn(mongoMsg(t, 1, 0, bson.D{
		{Key: "find", Value: "users"},
		{Key: "filter", Value: bson.D{{Key: "email", Value: "alice@example.com"}}},
		{Key: "$db", Value: "app"},
	})))
	backend := s.BackendConn(newFakeConn(mongoMsg(t, 2, 1, bson.D{{Key: "ok", Value: 1.0}})))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if _, present := recs[0]["statement"]; present {
		t.Errorf("statement present at metadata level: %v", recs[0]["statement"])
	}
	if recs[0]["op"] != "find" || recs[0]["collection"] != "users" {
		t.Errorf("metadata missing: %v", recs[0])
	}
	// A fingerprint is part of a metadata record, so the shape is computed
	// even though its text is not logged.
	if recs[0]["fingerprint"] == nil || recs[0]["fingerprint"] == "" {
		t.Error("fingerprint is missing at metadata level")
	}
}

// At full level the command is logged as the client sent it, values included.
func TestMongoTap_FullLevelLogsValues(t *testing.T) {
	s, records := newMongoTestSession(t, LevelFull)

	client := s.ClientConn(newFakeConn(mongoMsg(t, 1, 0, bson.D{
		{Key: "find", Value: "users"},
		{Key: "filter", Value: bson.D{{Key: "email", Value: "alice@example.com"}}},
		{Key: "$db", Value: "app"},
	})))
	backend := s.BackendConn(newFakeConn(mongoMsg(t, 2, 1, bson.D{{Key: "ok", Value: 1.0}})))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	stmt, _ := recs[0]["statement"].(string)
	if !strings.Contains(stmt, "alice@example.com") {
		t.Errorf("full level should log the value, got %q", stmt)
	}
}

// The fingerprint groups by shape, so it must not change when only the values
// differ — including at full level, where the logged text does change.
func TestMongoTap_FingerprintIgnoresValues(t *testing.T) {
	fingerprintFor := func(t *testing.T, email string) string {
		t.Helper()
		s, records := newMongoTestSession(t, LevelFull)
		client := s.ClientConn(newFakeConn(mongoMsg(t, 1, 0, bson.D{
			{Key: "find", Value: "users"},
			{Key: "filter", Value: bson.D{{Key: "email", Value: email}}},
			{Key: "$db", Value: "app"},
		})))
		backend := s.BackendConn(newFakeConn(mongoMsg(t, 2, 1, bson.D{{Key: "ok", Value: 1.0}})))
		drain(t, client)
		drain(t, backend)

		recs := records()
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		fp, _ := recs[0]["fingerprint"].(string)
		return fp
	}

	a := fingerprintFor(t, "alice@example.com")
	b := fingerprintFor(t, "bob@example.com")

	if a == "" {
		t.Fatal("fingerprint is empty")
	}
	if a != b {
		t.Errorf("fingerprint changed with the value: %s vs %s", a, b)
	}
}

func TestMongoTap_ErrorReply(t *testing.T) {
	s, records := newMongoTestSession(t, LevelMetadata)

	client := s.ClientConn(newFakeConn(mongoMsg(t, 5, 0, bson.D{{Key: "find", Value: "nope"}, {Key: "$db", Value: "app"}})))
	backend := s.BackendConn(newFakeConn(mongoMsg(t, 6, 5, bson.D{
		{Key: "ok", Value: 0.0},
		{Key: "errmsg", Value: "not authorized on app to execute command"},
		{Key: "code", Value: 13},
	})))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	errStr, _ := recs[0]["error"].(string)
	if !strings.Contains(errStr, "not authorized") {
		t.Errorf("error = %q, want the backend message", errStr)
	}
}

// Fire-and-forget writes never get a reply, so the pending map must not grow
// without bound.
func TestMongoTap_EvictsUnrepliedCommands(t *testing.T) {
	s, records := newMongoTestSession(t, LevelMetadata)

	var stream [][]byte
	total := maxPendingMongoCommands + 20
	for i := 0; i < total; i++ {
		stream = append(stream, mongoMsg(t, int32(i+1), 0, bson.D{
			{Key: "insert", Value: "events"},
			{Key: "$db", Value: "app"},
		}))
	}
	drain(t, s.ClientConn(newFakeConn(bytes.Join(stream, nil))))

	s.mu.Lock()
	pending := len(s.pending)
	s.mu.Unlock()

	if pending > maxPendingMongoCommands {
		t.Errorf("pending map holds %d entries, want at most %d", pending, maxPendingMongoCommands)
	}

	// Evicted commands are still reported rather than silently discarded.
	s.Close()
	if got := len(records()); got != total {
		t.Errorf("got %d records, want %d (every command accounted for)", got, total)
	}
}

// The proxy forwards the first post-handshake command itself, before the relay
// starts; LogCommand is how that one still reaches the log.
func TestMongoTap_LogCommandCoversTheFirstCommand(t *testing.T) {
	s, records := newMongoTestSession(t, LevelMetadata)

	raw, err := bson.Marshal(bson.D{{Key: "find", Value: "orders"}, {Key: "$db", Value: "shop"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg := &mongowire.Message{
		Header: mongowire.Header{RequestID: 42, OpCode: mongowire.OpMsg},
		Body:   mongowire.BuildOpMsg(0, raw),
	}
	s.LogCommand(msg)

	backend := s.BackendConn(newFakeConn(mongoMsg(t, 43, 42, bson.D{
		{Key: "cursor", Value: bson.D{{Key: "firstBatch", Value: bson.A{bson.D{{Key: "a", Value: 1}}}}}},
		{Key: "ok", Value: 1.0},
	})))
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0]["op"] != "find" || recs[0]["collection"] != "orders" {
		t.Errorf("record = %v, want the buffered find", recs[0])
	}
	if recs[0]["rows"] != float64(1) {
		t.Errorf("rows = %v, want 1", recs[0]["rows"])
	}
}

// LogReply is how the proxy reports the first command's response, which it
// reads directly rather than through the tap. Without it that exchange would
// be logged with no rows and no duration.
func TestMongoTap_LogReplyCompletesADirectExchange(t *testing.T) {
	s, records := newMongoTestSession(t, LevelMetadata)

	cmd, err := bson.Marshal(bson.D{{Key: "find", Value: "orders"}, {Key: "$db", Value: "shop"}})
	if err != nil {
		t.Fatalf("marshal command: %v", err)
	}
	s.LogCommand(&mongowire.Message{
		Header: mongowire.Header{RequestID: 7, OpCode: mongowire.OpMsg},
		Body:   mongowire.BuildOpMsg(0, cmd),
	})

	reply, err := bson.Marshal(bson.D{
		{Key: "cursor", Value: bson.D{{Key: "firstBatch", Value: bson.A{
			bson.D{{Key: "a", Value: 1}}, bson.D{{Key: "a", Value: 2}},
		}}}},
		{Key: "ok", Value: 1.0},
	})
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	s.LogReply(&mongowire.Message{
		Header: mongowire.Header{RequestID: 8, ResponseTo: 7, OpCode: mongowire.OpMsg},
		Body:   mongowire.BuildOpMsg(0, reply),
	})

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0]["op"] != "find" || recs[0]["collection"] != "orders" {
		t.Errorf("record = %v, want the find on orders", recs[0])
	}
	if recs[0]["rows"] != float64(2) {
		t.Errorf("rows = %v, want 2 from the reply batch", recs[0]["rows"])
	}
	if recs[0]["resp_bytes"] == float64(0) {
		t.Error("resp_bytes should reflect the reply size")
	}
}

// A reply that matches nothing pending must be ignored rather than attributed
// to an unrelated command.
func TestMongoTap_UnmatchedReplyIsIgnored(t *testing.T) {
	s, records := newMongoTestSession(t, LevelMetadata)

	backend := s.BackendConn(newFakeConn(mongoMsg(t, 2, 999, bson.D{{Key: "ok", Value: 1.0}})))
	drain(t, backend)

	if recs := records(); len(recs) != 0 {
		t.Errorf("an unmatched reply produced %d records: %v", len(recs), recs)
	}
}

func TestPlaceholderFor(t *testing.T) {
	tests := []struct {
		name string
		typ  bson.Type
		want string
	}{
		{"string", bson.TypeString, "?string"},
		{"int32", bson.TypeInt32, "?int"},
		{"int64", bson.TypeInt64, "?long"},
		{"double", bson.TypeDouble, "?double"},
		{"bool", bson.TypeBoolean, "?bool"},
		{"objectId", bson.TypeObjectID, "?objectId"},
		{"date", bson.TypeDateTime, "?date"},
		{"null", bson.TypeNull, "?null"},
		{"binary", bson.TypeBinary, "?binary"},
		{"regex", bson.TypeRegex, "?regex"},
		{"decimal", bson.TypeDecimal128, "?decimal"},
		{"timestamp", bson.TypeTimestamp, "?timestamp"},
		{"unknown falls back", bson.TypeMaxKey, "?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := placeholderFor(tt.typ); got != tt.want {
				t.Errorf("placeholderFor(%v) = %q, want %q", tt.typ, got, tt.want)
			}
		})
	}
}

// Every placeholder must be value-free: the point is that a shape can be
// logged where the data cannot.
func TestCommandShape_AllScalarTypesAreElided(t *testing.T) {
	raw, err := bson.Marshal(bson.D{
		{Key: "find", Value: "t"},
		{Key: "filter", Value: bson.D{
			{Key: "s", Value: "secret-value"},
			{Key: "i", Value: int32(4242)},
			{Key: "l", Value: int64(999999)},
			{Key: "d", Value: 3.5},
			{Key: "b", Value: true},
			{Key: "n", Value: nil},
			{Key: "bin", Value: bson.Binary{Data: []byte("bytes")}},
		}},
		{Key: "$db", Value: "app"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	shape := commandShape(bson.Raw(raw))
	for _, leaked := range []string{"secret-value", "4242", "999999", "3.5", "true", "bytes"} {
		if strings.Contains(shape, leaked) {
			t.Errorf("shape leaked %q: %s", leaked, shape)
		}
	}
	// Keys and the collection are structure, and must survive.
	for _, want := range []string{"find", `"t"`, "filter", "s:", "bin:"} {
		if !strings.Contains(shape, want) {
			t.Errorf("shape %q is missing %q", shape, want)
		}
	}
}

func TestMongoKind(t *testing.T) {
	tests := []struct {
		op   string
		want string
	}{
		{"find", KindRead},
		{"aggregate", KindRead},
		{"insert", KindWrite},
		{"update", KindWrite},
		{"delete", KindWrite},
		{"findAndModify", KindWrite},
		{"createIndexes", KindDDL},
		{"drop", KindDDL},
		{"commitTransaction", KindTCL},
		{"ping", KindUtility},
	}

	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			if got := mongoKind(tt.op); got != tt.want {
				t.Errorf("mongoKind(%q) = %q, want %q", tt.op, got, tt.want)
			}
		})
	}
}

func TestCommandShape_ArraysAndNesting(t *testing.T) {
	raw, err := bson.Marshal(bson.D{
		{Key: "insert", Value: "events"},
		{Key: "documents", Value: bson.A{
			bson.D{{Key: "user", Value: "alice"}, {Key: "n", Value: 1}},
			bson.D{{Key: "user", Value: "bob"}, {Key: "n", Value: 2}},
		}},
		{Key: "$db", Value: "app"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	shape := commandShape(bson.Raw(raw))
	for _, leaked := range []string{"alice", "bob"} {
		if strings.Contains(shape, leaked) {
			t.Errorf("shape leaked %q: %s", leaked, shape)
		}
	}
	for _, want := range []string{"insert", "events", "documents", "user", "?string", "..."} {
		if !strings.Contains(shape, want) {
			t.Errorf("shape %q is missing %q", shape, want)
		}
	}
}
