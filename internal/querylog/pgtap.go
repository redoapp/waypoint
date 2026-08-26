package querylog

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Postgres frontend (client → backend) message types we care about.
const (
	pgMsgQuery     = 'Q'
	pgMsgParse     = 'P'
	pgMsgBind      = 'B'
	pgMsgExecute   = 'E'
	pgMsgTerminate = 'X'
)

// Postgres backend (backend → client) message types we care about. Note that
// 'E' means Execute from the client and ErrorResponse from the backend; the
// two directions are framed by separate taps, so there is no ambiguity.
const (
	pgMsgDataRow            = 'D'
	pgMsgCommandComplete    = 'C'
	pgMsgErrorResponse      = 'E'
	pgMsgEmptyQueryResponse = 'I'
	pgMsgReadyForQuery      = 'Z'
	pgMsgPortalSuspended    = 's'
)

// maxPendingStatements bounds the in-flight statement queue. A client that
// pipelines without ever reading responses cannot grow it without limit.
const maxPendingStatements = 64

// pgPending is one statement awaiting its response.
type pgPending struct {
	sql    string
	params []string
	start  time.Time

	// simple marks a statement from the simple query protocol ('Q'). A
	// single 'Q' may contain several statements and therefore produce
	// several CommandComplete messages, so its counters accumulate until
	// ReadyForQuery rather than finalizing on the first one.
	simple bool

	// Row counting has two sources. dataRows counts DataRow messages, which
	// is all a plain SELECT gives us. tagRows sums the counts in
	// CommandComplete tags, which is the only source that works for writes —
	// an UPDATE returns no rows but reports how many it changed. The tag
	// wins when present, and sums across statements so a simple query
	// carrying several of them reports the total rather than just the last.
	dataRows  int64
	tagRows   int64
	sawTagRow bool

	respBytes int64
	errMsg    string
	completed bool
}

// rows returns the best available row count for the statement.
func (p *pgPending) rows() int64 {
	if p.sawTagRow {
		return p.tagRows
	}
	return p.dataRows
}

// PGSession correlates client statements with backend responses for one
// Postgres connection. Both taps share it, so it is mutex-guarded: the relay
// runs a goroutine per direction.
type PGSession struct {
	emitter *Emitter
	base    Event

	mu          sync.Mutex
	pending     []*pgPending
	prepared    map[string]string   // prepared statement name → SQL
	portals     map[string]string   // portal name → prepared statement name
	boundParams map[string][]string // portal name → bind parameter values

	// lastParse remembers the most recent Parse so a statement rejected at
	// prepare time still gets logged. Such a statement never reaches Execute,
	// so without this it would leave no record at all — and a statement the
	// backend refused is one worth auditing.
	lastParse *pgPending

	// errorInBatch records that the backend rejected something in the current
	// extended-protocol batch. Everything after an error is discarded until
	// Sync, so the queued statements that never ran can be cleared at
	// ReadyForQuery instead of lingering.
	errorInBatch bool
}

// NewPGSession creates the correlation state for one connection. base supplies
// the connection-scoped fields (conn id, listener, user, database, level).
func NewPGSession(emitter *Emitter, base Event) *PGSession {
	base.Mode = ModePostgres
	return &PGSession{
		emitter:     emitter,
		base:        base,
		prepared:    make(map[string]string),
		portals:     make(map[string]string),
		boundParams: make(map[string][]string),
	}
}

// ClientConn wraps the client side of the connection so statements the client
// sends are observed on their way to the backend.
func (s *PGSession) ClientConn(c net.Conn) net.Conn {
	return &framedConn{
		conn:             c,
		readHeader:       pgReadHeader,
		observe:          s.observeClient,
		observeOversized: s.observeOversizedClient,
	}
}

// BackendConn wraps the backend side so responses can be attributed back to
// the statement that caused them.
func (s *PGSession) BackendConn(c net.Conn) net.Conn {
	return &framedConn{
		conn:       c,
		readHeader: pgReadHeader,
		observe:    s.observeBackend,
	}
}

// pgReadHeader reads a 5-byte Postgres message header: a type byte followed by
// a big-endian length that counts itself but not the type byte.
func pgReadHeader(r io.Reader) ([]byte, int, error) {
	hdr := make([]byte, 5)
	n, err := io.ReadFull(r, hdr)
	if err != nil {
		return hdr[:n], 0, err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 {
		return hdr, 0, nil // malformed; caller passes it through
	}
	return hdr, int(length) + 1, nil
}

func (s *PGSession) observeClient(msg []byte) {
	body := msg[5:]

	switch msg[0] {
	case pgMsgQuery:
		var q pgproto3.Query
		if err := q.Decode(body); err != nil {
			return
		}
		s.push(&pgPending{sql: q.String, start: time.Now(), simple: true})

	case pgMsgParse:
		var p pgproto3.Parse
		if err := p.Decode(body); err != nil {
			return
		}
		s.mu.Lock()
		// Bound the map: a client that prepares unboundedly many statements
		// should not be able to grow this without limit.
		if len(s.prepared) >= maxPendingStatements*4 {
			s.prepared = make(map[string]string)
		}
		s.prepared[p.Name] = p.Query
		s.lastParse = &pgPending{sql: p.Query, start: time.Now()}
		s.mu.Unlock()

	case pgMsgBind:
		var b pgproto3.Bind
		if err := b.Decode(body); err != nil {
			return
		}
		s.mu.Lock()
		if len(s.portals) >= maxPendingStatements*4 {
			s.portals = make(map[string]string)
		}
		s.portals[b.DestinationPortal] = b.PreparedStatement
		s.mu.Unlock()

		if s.base.Level >= LevelFull {
			s.setBindParams(b.DestinationPortal, renderParams(b.Parameters))
		}

	case pgMsgExecute:
		var ex pgproto3.Execute
		if err := ex.Decode(body); err != nil {
			return
		}
		s.mu.Lock()
		stmtName := s.portals[ex.Portal]
		sql := s.prepared[stmtName]
		params := s.boundParams[ex.Portal]
		s.mu.Unlock()

		// An Execute against a portal we never saw bound leaves sql empty:
		// the Bind predates the tap, or the client is pipelining oddly. The
		// entry is still queued so the response is attributed to something
		// rather than sliding onto the next statement.
		s.push(&pgPending{sql: sql, params: params, start: time.Now()})

	case pgMsgTerminate:
		s.flushAll()
	}
}

// observeOversizedClient notes a statement too large to buffer. Its text is
// never held in memory or parsed, but the fact that a multi-megabyte statement
// ran still belongs in the audit trail rather than vanishing from it.
//
// Only statement-carrying messages are reported. Bulk CopyData frames are the
// payload of a COPY, not statements in their own right, and logging one record
// per frame would bury the statement that started it.
func (s *PGSession) observeOversizedClient(hdr []byte, total int) {
	if len(hdr) == 0 {
		return
	}

	var op string
	switch hdr[0] {
	case pgMsgQuery:
		op = "QUERY"
	case pgMsgParse:
		op = "PARSE"
	default:
		return
	}

	ev := s.base
	ev.Op = op
	ev.Kind = KindUnknown
	ev.ReqBytes = int64(total)
	ev.Truncated = true
	s.emitter.Log(&ev)
}

func (s *PGSession) observeBackend(msg []byte) {
	body := msg[5:]

	s.mu.Lock()
	defer s.mu.Unlock()

	head := s.head()
	if head != nil {
		head.respBytes += int64(len(msg))
	}

	switch msg[0] {
	case pgMsgDataRow:
		if head != nil {
			head.dataRows++
		}

	case pgMsgCommandComplete:
		var cc pgproto3.CommandComplete
		if err := cc.Decode(body); err != nil {
			return
		}
		if head == nil {
			return
		}
		if n, ok := rowsFromCommandTag(string(cc.CommandTag)); ok {
			// The tag is authoritative — it counts rows the backend acted
			// on, which for INSERT/UPDATE/DELETE the DataRow count misses
			// entirely.
			head.tagRows += n
			head.sawTagRow = true
		}
		head.completed = true
		if !head.simple {
			s.finalizeHead()
		}

	case pgMsgErrorResponse:
		var er pgproto3.ErrorResponse
		if err := er.Decode(body); err != nil {
			return
		}
		msg := formatPGError(&er)
		if head == nil {
			// No statement is in flight, so this is a failure during Parse or
			// Describe: the statement was rejected before it could execute.
			if s.lastParse != nil {
				failed := s.lastParse
				s.lastParse = nil
				failed.errMsg = msg
				s.emitLocked(failed)
			}
			return
		}
		head.errMsg = msg
		head.completed = true
		s.errorInBatch = true
		s.finalizeHead()

	case pgMsgEmptyQueryResponse, pgMsgPortalSuspended:
		if head == nil {
			return
		}
		head.completed = true
		if !head.simple {
			s.finalizeHead()
		}

	case pgMsgReadyForQuery:
		// End of one statement batch. A simple query may contain several
		// statements and so produce several CommandCompletes, which is why
		// its entry accumulates until here rather than finalizing on the
		// first one — but only *one* entry is retired, since a client that
		// pipelines two Query messages gets two ReadyForQuery messages and
		// its second statement's results have not arrived yet.
		if head != nil && head.completed {
			s.finalizeHead()
		}

		// Anything still queued after an error was discarded by the backend
		// without ever running, so it will never get a response.
		if s.errorInBatch {
			s.finalizeAllLocked()
		}

		s.errorInBatch = false
		s.lastParse = nil
	}
}

func (s *PGSession) head() *pgPending {
	if len(s.pending) == 0 {
		return nil
	}
	return s.pending[0]
}

func (s *PGSession) push(p *pgPending) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.pending) >= maxPendingStatements {
		// Drop the oldest rather than grow without bound. Its response was
		// never observed, so emit what we know instead of losing it.
		oldest := s.pending[0]
		s.pending = s.pending[1:]
		s.emitLocked(oldest)
	}
	s.pending = append(s.pending, p)
}

func (s *PGSession) setBindParams(portal string, params []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.boundParams) >= maxPendingStatements*4 {
		s.boundParams = make(map[string][]string)
	}
	s.boundParams[portal] = params
}

func (s *PGSession) finalizeHead() {
	if len(s.pending) == 0 {
		return
	}
	p := s.pending[0]
	s.pending = s.pending[1:]
	s.emitLocked(p)
}

func (s *PGSession) finalizeAllLocked() {
	for len(s.pending) > 0 {
		p := s.pending[0]
		s.pending = s.pending[1:]
		s.emitLocked(p)
	}
}

func (s *PGSession) flushAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finalizeAllLocked()
}

func (s *PGSession) emitLocked(p *pgPending) {
	if p == nil || p.sql == "" && p.rows() == 0 && p.respBytes == 0 {
		return
	}
	ev := s.base
	ev.RawStatement = p.sql
	ev.Params = p.params
	ev.Rows = p.rows()
	ev.RespBytes = p.respBytes
	ev.Duration = time.Since(p.start)
	ev.Err = p.errMsg
	s.emitter.Log(&ev)
}

// Close flushes any statement still awaiting a response, so a connection that
// drops mid-query still leaves a record behind.
func (s *PGSession) Close() {
	s.flushAll()
}

// rowsFromCommandTag pulls the row count out of a CommandComplete tag:
// "SELECT 42", "INSERT 0 5", "UPDATE 3". Tags without a count ("CREATE TABLE")
// report false.
func rowsFromCommandTag(tag string) (int64, bool) {
	fields := strings.Fields(tag)
	if len(fields) < 2 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func formatPGError(er *pgproto3.ErrorResponse) string {
	if er.Code != "" && er.Message != "" {
		return fmt.Sprintf("%s: %s", er.Code, er.Message)
	}
	if er.Message != "" {
		return er.Message
	}
	return er.Code
}

// renderParams turns bind parameter values into loggable strings. Text
// parameters pass through; binary ones are hex-encoded so a record is never
// corrupted by raw bytes.
func renderParams(params [][]byte) []string {
	if len(params) == 0 {
		return nil
	}
	out := make([]string, 0, len(params))
	for _, p := range params {
		switch {
		case p == nil:
			out = append(out, "NULL")
		case utf8.Valid(p) && !hasControlBytes(p):
			out = append(out, string(p))
		default:
			out = append(out, "\\x"+hex.EncodeToString(p))
		}
	}
	return out
}

func hasControlBytes(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
	}
	return false
}
