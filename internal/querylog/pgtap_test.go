package querylog

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// fakeConn serves a fixed byte stream on Read and captures writes.
type fakeConn struct {
	r *bytes.Reader
	w bytes.Buffer
}

func newFakeConn(data []byte) *fakeConn { return &fakeConn{r: bytes.NewReader(data)} }

func (c *fakeConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "fake" }
func (dummyAddr) String() string  { return "fake" }

func encodeAll(t *testing.T, msgs ...interface{ Encode([]byte) ([]byte, error) }) []byte {
	t.Helper()
	var out []byte
	for _, m := range msgs {
		var err error
		out, err = m.Encode(out)
		if err != nil {
			t.Fatalf("encoding %T: %v", m, err)
		}
	}
	return out
}

// newTestSession builds a session whose events land in a slice.
func newTestSession(t *testing.T, level Level) (*PGSession, func() []map[string]any) {
	t.Helper()
	logger, records := captureLogger(t)
	emitter := NewEmitter(logger, 8192, Counters{})
	t.Cleanup(emitter.Close)

	s := NewPGSession(emitter, Event{
		ConnID:   "conn1",
		Listener: "pg-test",
		User:     "alice@example.com",
		Database: "app",
		Level:    level,
	})
	return s, func() []map[string]any {
		emitter.Close()
		return records()
	}
}

// TestPGTap_BytesPassThroughUnchanged is the invariant the whole design rests
// on: the tap sits inside restrict.Relay, whose byte counting enforces the
// per-user bandwidth limits, so it must hand on exactly the bytes it received.
func TestPGTap_BytesPassThroughUnchanged(t *testing.T) {
	stream := encodeAll(t,
		&pgproto3.Query{String: "SELECT 1"},
		&pgproto3.Parse{Name: "s1", Query: "SELECT * FROM t WHERE id = $1"},
		&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "s1", Parameters: [][]byte{[]byte("7")}},
		&pgproto3.Execute{Portal: ""},
		&pgproto3.Sync{},
		&pgproto3.Query{String: "SELECT " + strings.Repeat("x", 5000)},
		&pgproto3.Terminate{},
	)

	// Small read buffers force the framer through its buffering path.
	for _, bufSize := range []int{1, 3, 7, 64, 512, 4096, 65536} {
		t.Run(fmt.Sprintf("%d-byte reads", bufSize), func(t *testing.T) {
			s, _ := newTestSession(t, LevelMetadata)
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
				t.Errorf("stream corrupted with %d-byte reads: got %d bytes, want %d",
					bufSize, got.Len(), len(stream))
			}
		})
	}
}

// drain reads a conn to EOF, discarding the bytes.
func drain(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := io.Copy(io.Discard, c); err != nil && err != io.EOF {
		t.Fatalf("draining: %v", err)
	}
}

func TestPGTap_SimpleQuery(t *testing.T) {
	s, records := newTestSession(t, LevelNormalized)

	client := s.ClientConn(newFakeConn(encodeAll(t,
		&pgproto3.Query{String: "SELECT * FROM orders WHERE id = 42"},
	)))
	backend := s.BackendConn(newFakeConn(encodeAll(t,
		&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("id")}}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
		&pgproto3.DataRow{Values: [][]byte{[]byte("2")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)))

	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1: %v", len(recs), recs)
	}
	r := recs[0]

	if r["op"] != "SELECT" {
		t.Errorf("op = %v, want SELECT", r["op"])
	}
	if r["rows"] != float64(2) {
		t.Errorf("rows = %v, want 2", r["rows"])
	}
	if stmt, _ := r["statement"].(string); strings.Contains(stmt, "42") {
		t.Errorf("normalized statement leaked the literal: %q", stmt)
	}
	if r["conn_id"] != "conn1" || r["user"] != "alice@example.com" || r["database"] != "app" {
		t.Errorf("connection identity missing from record: %v", r)
	}
}

// The CommandComplete tag is authoritative for writes, where counting DataRow
// messages would report zero.
func TestPGTap_RowCountFromCommandTag(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		tag      string
		wantRows float64
	}{
		{"select", "SELECT * FROM t", "SELECT 7", 7},
		{"insert", "INSERT INTO t VALUES (1)", "INSERT 0 5", 5},
		{"update", "UPDATE t SET a = 1", "UPDATE 3", 3},
		{"delete", "DELETE FROM t", "DELETE 9", 9},
		{"ddl has no count", "CREATE TABLE t (a INT)", "CREATE TABLE", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, records := newTestSession(t, LevelMetadata)

			client := s.ClientConn(newFakeConn(encodeAll(t, &pgproto3.Query{String: tt.sql})))
			backend := s.BackendConn(newFakeConn(encodeAll(t,
				&pgproto3.CommandComplete{CommandTag: []byte(tt.tag)},
				&pgproto3.ReadyForQuery{TxStatus: 'I'},
			)))
			drain(t, client)
			drain(t, backend)

			recs := records()
			if len(recs) != 1 {
				t.Fatalf("got %d records, want 1", len(recs))
			}
			if recs[0]["rows"] != tt.wantRows {
				t.Errorf("rows = %v, want %v", recs[0]["rows"], tt.wantRows)
			}
		})
	}
}

func TestPGTap_ExtendedProtocolUsesPreparedText(t *testing.T) {
	s, records := newTestSession(t, LevelFull)

	client := s.ClientConn(newFakeConn(encodeAll(t,
		&pgproto3.Parse{Name: "s1", Query: "SELECT * FROM users WHERE id = $1"},
		&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "s1", Parameters: [][]byte{[]byte("77")}},
		&pgproto3.Execute{Portal: "p1"},
		&pgproto3.Sync{},
	)))
	backend := s.BackendConn(newFakeConn(encodeAll(t,
		&pgproto3.DataRow{Values: [][]byte{[]byte("77")}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1: %v", len(recs), recs)
	}
	r := recs[0]

	// The Execute message names only a portal; the statement text has to come
	// from the earlier Parse.
	if stmt, _ := r["statement"].(string); !strings.Contains(stmt, "users") {
		t.Errorf("statement = %q, want the prepared statement text", stmt)
	}
	if r["op"] != "SELECT" {
		t.Errorf("op = %v, want SELECT", r["op"])
	}
	params, _ := r["params"].([]any)
	if len(params) != 1 || params[0] != "77" {
		t.Errorf("params = %v, want [77]", r["params"])
	}
}

// Bind parameters are row data and must not appear below LevelFull.
func TestPGTap_ParamsOnlyAtFullLevel(t *testing.T) {
	for _, level := range []Level{LevelMetadata, LevelNormalized} {
		t.Run(level.String(), func(t *testing.T) {
			s, records := newTestSession(t, level)

			client := s.ClientConn(newFakeConn(encodeAll(t,
				&pgproto3.Parse{Name: "s1", Query: "SELECT * FROM users WHERE ssn = $1"},
				&pgproto3.Bind{DestinationPortal: "", PreparedStatement: "s1", Parameters: [][]byte{[]byte("123-45-6789")}},
				&pgproto3.Execute{Portal: ""},
			)))
			backend := s.BackendConn(newFakeConn(encodeAll(t,
				&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
				&pgproto3.ReadyForQuery{TxStatus: 'I'},
			)))
			drain(t, client)
			drain(t, backend)

			recs := records()
			if len(recs) != 1 {
				t.Fatalf("got %d records, want 1", len(recs))
			}
			if _, present := recs[0]["params"]; present {
				t.Errorf("params leaked at level %v: %v", level, recs[0]["params"])
			}
		})
	}
}

func TestPGTap_ErrorResponseIsAttributed(t *testing.T) {
	s, records := newTestSession(t, LevelMetadata)

	client := s.ClientConn(newFakeConn(encodeAll(t,
		&pgproto3.Query{String: "SELECT * FROM missing_table"},
	)))
	backend := s.BackendConn(newFakeConn(encodeAll(t,
		&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: "relation \"missing_table\" does not exist"},
		&pgproto3.ReadyForQuery{TxStatus: 'E'},
	)))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	errStr, _ := recs[0]["error"].(string)
	if !strings.Contains(errStr, "42P01") || !strings.Contains(errStr, "missing_table") {
		t.Errorf("error = %q, want the SQLSTATE and message", errStr)
	}
}

// A pipelined batch must attribute each response to its own statement rather
// than collapsing them onto the first.
func TestPGTap_PipelinedExecutesEachGetARecord(t *testing.T) {
	s, records := newTestSession(t, LevelNormalized)

	client := s.ClientConn(newFakeConn(encodeAll(t,
		&pgproto3.Parse{Name: "a", Query: "SELECT * FROM alpha"},
		&pgproto3.Bind{DestinationPortal: "pa", PreparedStatement: "a"},
		&pgproto3.Execute{Portal: "pa"},
		&pgproto3.Parse{Name: "b", Query: "SELECT * FROM beta"},
		&pgproto3.Bind{DestinationPortal: "pb", PreparedStatement: "b"},
		&pgproto3.Execute{Portal: "pb"},
		&pgproto3.Sync{},
	)))
	backend := s.BackendConn(newFakeConn(encodeAll(t,
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %v", len(recs), recs)
	}

	first, _ := recs[0]["statement"].(string)
	second, _ := recs[1]["statement"].(string)
	if !strings.Contains(first, "alpha") {
		t.Errorf("first record = %q, want the alpha statement", first)
	}
	if !strings.Contains(second, "beta") {
		t.Errorf("second record = %q, want the beta statement", second)
	}
	if recs[0]["rows"] != float64(1) || recs[1]["rows"] != float64(2) {
		t.Errorf("row counts mis-attributed: %v then %v", recs[0]["rows"], recs[1]["rows"])
	}
}

// An oversized message streams through without being buffered or decoded; the
// bytes must still arrive intact.
func TestPGTap_OversizedMessageStreamsThrough(t *testing.T) {
	huge := &pgproto3.Query{String: "SELECT '" + strings.Repeat("z", maxBufferedMessage+1024) + "'"}
	stream := encodeAll(t, huge, &pgproto3.Terminate{})

	s, records := newTestSession(t, LevelNormalized)
	tap := s.ClientConn(newFakeConn(stream))

	var got bytes.Buffer
	if _, err := io.Copy(&got, tap); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if !bytes.Equal(got.Bytes(), stream) {
		t.Fatalf("oversized message was corrupted: got %d bytes, want %d", got.Len(), len(stream))
	}

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0]["op"] != "QUERY" {
		t.Errorf("op = %v, want QUERY", recs[0]["op"])
	}
	if recs[0]["truncated"] != true {
		t.Errorf("truncated = %v, want true", recs[0]["truncated"])
	}
	// The size belongs on the request, not the response.
	reqBytes, _ := recs[0]["req_bytes"].(float64)
	if reqBytes < float64(maxBufferedMessage) {
		t.Errorf("req_bytes = %v, want at least the buffering threshold", recs[0]["req_bytes"])
	}
	if _, present := recs[0]["statement"]; present {
		t.Errorf("an oversized statement must not be buffered into the log: %v", recs[0]["statement"])
	}
}

// A connection that drops mid-statement should still leave a record.
func TestPGTap_CloseFlushesInFlightStatement(t *testing.T) {
	s, records := newTestSession(t, LevelMetadata)

	client := s.ClientConn(newFakeConn(encodeAll(t, &pgproto3.Query{String: "SELECT pg_sleep(60)"})))
	drain(t, client)
	s.Close()

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0]["op"] != "SELECT" {
		t.Errorf("op = %v, want SELECT", recs[0]["op"])
	}
}

func TestRowsFromCommandTag(t *testing.T) {
	tests := []struct {
		tag   string
		rows  int64
		found bool
	}{
		{"SELECT 42", 42, true},
		{"INSERT 0 5", 5, true},
		{"UPDATE 0", 0, true},
		{"DELETE 12", 12, true},
		{"CREATE TABLE", 0, false},
		{"BEGIN", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			rows, ok := rowsFromCommandTag(tt.tag)
			if ok != tt.found || rows != tt.rows {
				t.Errorf("rowsFromCommandTag(%q) = (%d, %v), want (%d, %v)", tt.tag, rows, ok, tt.rows, tt.found)
			}
		})
	}
}

func TestRenderParams(t *testing.T) {
	got := renderParams([][]byte{[]byte("plain"), nil, {0x00, 0xff}})
	want := []string{"plain", "NULL", "\\x00ff"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("param %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A statement rejected at prepare time never reaches Execute. Without special
// handling it would leave no record at all — and a statement the backend
// refused is exactly one worth auditing.
func TestPGTap_ParseTimeErrorIsLogged(t *testing.T) {
	s, records := newTestSession(t, LevelNormalized)

	// pgx sends Parse/Describe/Sync as their own round trip, so a bad
	// statement fails before any Bind or Execute is sent.
	client := s.ClientConn(newFakeConn(encodeAll(t,
		&pgproto3.Parse{Name: "s1", Query: "SELECT id FROM absent_table"},
		&pgproto3.Describe{ObjectType: 'S', Name: "s1"},
		&pgproto3.Sync{},
	)))
	backend := s.BackendConn(newFakeConn(encodeAll(t,
		&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: `relation "absent_table" does not exist`},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1: %v", len(recs), recs)
	}
	stmt, _ := recs[0]["statement"].(string)
	if !strings.Contains(stmt, "absent_table") {
		t.Errorf("statement = %q, want the rejected statement", stmt)
	}
	errStr, _ := recs[0]["error"].(string)
	if !strings.Contains(errStr, "42P01") {
		t.Errorf("error = %q, want the SQLSTATE", errStr)
	}
}

// A prepare that succeeds must not have a later, unrelated error attributed
// back to it.
func TestPGTap_SuccessfulParseIsNotBlamedForLaterErrors(t *testing.T) {
	s, records := newTestSession(t, LevelNormalized)

	client := s.ClientConn(newFakeConn(encodeAll(t,
		&pgproto3.Parse{Name: "s1", Query: "SELECT * FROM fine_table"},
		&pgproto3.Sync{},
	)))
	backend := s.BackendConn(newFakeConn(encodeAll(t,
		&pgproto3.ParseComplete{},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
		// A later error with nothing in flight must not be blamed on the
		// statement prepared in the previous round trip.
		&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceling statement"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)))
	drain(t, client)
	drain(t, backend)

	if recs := records(); len(recs) != 0 {
		t.Errorf("expected no records for a bare prepare, got %v", recs)
	}
}

// A simple Query may hold several statements and so produce several
// CommandComplete messages, which must collapse into one record — but two
// pipelined Query messages are two separate statements and must not.
func TestPGTap_SimpleQueryBatching(t *testing.T) {
	t.Run("one Query with several statements yields one record", func(t *testing.T) {
		s, records := newTestSession(t, LevelNormalized)

		client := s.ClientConn(newFakeConn(encodeAll(t,
			&pgproto3.Query{String: "SELECT * FROM alpha; SELECT * FROM beta"},
		)))
		backend := s.BackendConn(newFakeConn(encodeAll(t,
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		)))
		drain(t, client)
		drain(t, backend)

		recs := records()
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1: %v", len(recs), recs)
		}
		// One record covering both statements should report their total,
		// not just whichever finished last.
		if recs[0]["rows"] != float64(3) {
			t.Errorf("rows = %v, want 3 (1 + 2 across both statements)", recs[0]["rows"])
		}
	})

	t.Run("returned rows are not double counted against the tag", func(t *testing.T) {
		s, records := newTestSession(t, LevelNormalized)

		client := s.ClientConn(newFakeConn(encodeAll(t,
			&pgproto3.Query{String: "SELECT * FROM alpha"},
		)))
		backend := s.BackendConn(newFakeConn(encodeAll(t,
			&pgproto3.DataRow{Values: [][]byte{[]byte("1")}},
			&pgproto3.DataRow{Values: [][]byte{[]byte("2")}},
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		)))
		drain(t, client)
		drain(t, backend)

		recs := records()
		if len(recs) != 1 {
			t.Fatalf("got %d records, want 1", len(recs))
		}
		if recs[0]["rows"] != float64(2) {
			t.Errorf("rows = %v, want 2 (the tag, not tag + DataRow count)", recs[0]["rows"])
		}
	})

	t.Run("two pipelined Query messages yield two records", func(t *testing.T) {
		s, records := newTestSession(t, LevelNormalized)

		client := s.ClientConn(newFakeConn(encodeAll(t,
			&pgproto3.Query{String: "SELECT * FROM alpha"},
			&pgproto3.Query{String: "SELECT * FROM beta"},
		)))
		backend := s.BackendConn(newFakeConn(encodeAll(t,
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 2")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		)))
		drain(t, client)
		drain(t, backend)

		recs := records()
		if len(recs) != 2 {
			t.Fatalf("got %d records, want 2: %v", len(recs), recs)
		}

		first, _ := recs[0]["statement"].(string)
		second, _ := recs[1]["statement"].(string)
		if !strings.Contains(first, "alpha") {
			t.Errorf("first record = %q, want the alpha statement", first)
		}
		if !strings.Contains(second, "beta") {
			t.Errorf("second record = %q, want the beta statement", second)
		}
		// Each row count must land on its own statement rather than both
		// collapsing onto the first.
		if recs[0]["rows"] != float64(1) || recs[1]["rows"] != float64(2) {
			t.Errorf("row counts mis-attributed: %v then %v", recs[0]["rows"], recs[1]["rows"])
		}
	})
}

// After the backend rejects part of an extended-protocol batch it discards
// everything until Sync, so the statements that never ran should be cleared
// rather than left to be blamed for a later statement's response.
func TestPGTap_BatchAbortedByErrorIsCleared(t *testing.T) {
	s, records := newTestSession(t, LevelNormalized)

	client := s.ClientConn(newFakeConn(encodeAll(t,
		&pgproto3.Parse{Name: "a", Query: "SELECT * FROM alpha"},
		&pgproto3.Bind{DestinationPortal: "pa", PreparedStatement: "a"},
		&pgproto3.Execute{Portal: "pa"},
		&pgproto3.Parse{Name: "b", Query: "SELECT * FROM beta"},
		&pgproto3.Bind{DestinationPortal: "pb", PreparedStatement: "b"},
		&pgproto3.Execute{Portal: "pb"},
		&pgproto3.Sync{},
	)))
	backend := s.BackendConn(newFakeConn(encodeAll(t,
		// The first statement fails; the second never runs.
		&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42P01", Message: "boom"},
		&pgproto3.ReadyForQuery{TxStatus: 'E'},
	)))
	drain(t, client)
	drain(t, backend)

	recs := records()
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (the failure and the discarded statement): %v", len(recs), recs)
	}

	errStr, _ := recs[0]["error"].(string)
	if !strings.Contains(errStr, "42P01") {
		t.Errorf("first record should carry the error, got %q", errStr)
	}

	// The discarded statement is reported, but must not have inherited the
	// first statement's error.
	if second, _ := recs[1]["error"].(string); second != "" {
		t.Errorf("discarded statement should not carry an error, got %q", second)
	}

	// Nothing should still be queued.
	s.mu.Lock()
	pending := len(s.pending)
	s.mu.Unlock()
	if pending != 0 {
		t.Errorf("%d statements still queued after the batch aborted", pending)
	}
}
