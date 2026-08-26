package querylog

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureLogger returns a logger writing JSON into a buffer, plus a function
// that decodes the records written so far.
func captureLogger(t *testing.T) (*slog.Logger, func() []map[string]any) {
	t.Helper()

	buf := &bytes.Buffer{}
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(&lockedWriter{w: buf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelDebug}))

	return logger, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()

		var records []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("decoding log line %q: %v", line, err)
			}
			records = append(records, rec)
		}
		return records
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestEmitter_DerivesPostgresMetadata(t *testing.T) {
	logger, records := captureLogger(t)
	e := NewEmitter(logger, 16, Counters{})

	e.Log(&Event{
		ConnID:       "abc123",
		Listener:     "pg-prod",
		User:         "alice@example.com",
		Mode:         ModePostgres,
		Database:     "app",
		Level:        LevelNormalized,
		RawStatement: "SELECT o.* FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = 42",
		Rows:         3,
		RespBytes:    128,
		Duration:     2500 * time.Microsecond,
	})
	e.Close()

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]

	if r["msg"] != "query" {
		t.Errorf("msg = %v, want \"query\"", r["msg"])
	}
	if r["component"] != "querylog" {
		t.Errorf("component = %v, want \"querylog\"", r["component"])
	}
	if r["op"] != "SELECT" {
		t.Errorf("op = %v, want SELECT", r["op"])
	}
	if r["kind"] != KindRead {
		t.Errorf("kind = %v, want %v", r["kind"], KindRead)
	}
	if r["user"] != "alice@example.com" {
		t.Errorf("user = %v", r["user"])
	}
	if r["rows"] != float64(3) {
		t.Errorf("rows = %v, want 3", r["rows"])
	}
	if r["duration_ms"] != 2.5 {
		t.Errorf("duration_ms = %v, want 2.5", r["duration_ms"])
	}
	if r["fingerprint"] == nil || r["fingerprint"] == "" {
		t.Error("fingerprint is missing")
	}

	tables, _ := r["tables"].([]any)
	if len(tables) != 2 {
		t.Fatalf("tables = %v, want two entries", r["tables"])
	}
	if tables[0] != "orders" || tables[1] != "users" {
		t.Errorf("tables = %v, want [orders users]", tables)
	}

	stmt, _ := r["statement"].(string)
	if strings.Contains(stmt, "42") {
		t.Errorf("normalized statement still contains the literal: %q", stmt)
	}
}

func TestEmitter_LevelControlsStatementText(t *testing.T) {
	const raw = "SELECT * FROM users WHERE email = 'alice@example.com'"

	tests := []struct {
		name         string
		level        Level
		wantStmt     bool
		wantLiteral  bool
		wantRecorded bool
	}{
		{"off emits nothing", LevelOff, false, false, false},
		{"metadata omits statement", LevelMetadata, false, false, true},
		{"normalized hides the literal", LevelNormalized, true, false, true},
		{"full includes the literal", LevelFull, true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, records := captureLogger(t)
			e := NewEmitter(logger, 16, Counters{})
			e.Log(&Event{Mode: ModePostgres, Level: tt.level, RawStatement: raw})
			e.Close()

			recs := records()
			if !tt.wantRecorded {
				if len(recs) != 0 {
					t.Fatalf("level %v produced %d records, want none", tt.level, len(recs))
				}
				return
			}
			if len(recs) != 1 {
				t.Fatalf("got %d records, want 1", len(recs))
			}

			stmt, present := recs[0]["statement"].(string)
			if present != tt.wantStmt {
				t.Errorf("statement present = %v, want %v (got %q)", present, tt.wantStmt, stmt)
			}
			if got := strings.Contains(stmt, "alice@example.com"); got != tt.wantLiteral {
				t.Errorf("literal present = %v, want %v (statement %q)", got, tt.wantLiteral, stmt)
			}
		})
	}
}

// A statement the parser rejects is reported in full even at metadata level,
// where nothing else carries statement text.
func TestEmitter_ParseFailureLogsRawStatementAtMetadata(t *testing.T) {
	const raw = "SELCT * FROM orders WHERE id = 42"

	logger, records := captureLogger(t)
	var parseErrors int64
	e := NewEmitter(logger, 16, Counters{
		ParseErrors: func(_ context.Context, n int64, _ string) { parseErrors += n },
	})
	e.Log(&Event{Mode: ModePostgres, Level: LevelMetadata, RawStatement: raw})
	e.Close()

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0]["parse_error"] != true {
		t.Errorf("parse_error = %v, want true", recs[0]["parse_error"])
	}
	if recs[0]["statement"] != raw {
		t.Errorf("statement = %v, want the raw text %q", recs[0]["statement"], raw)
	}
	if parseErrors != 1 {
		t.Errorf("parse error counter = %d, want 1", parseErrors)
	}
}

func TestEmitter_TruncatesStatement(t *testing.T) {
	long := "SELECT * FROM t WHERE x = '" + strings.Repeat("a", 500) + "'"

	logger, records := captureLogger(t)
	e := NewEmitter(logger, 16, Counters{})
	e.Log(&Event{Mode: ModePostgres, Level: LevelFull, RawStatement: long, MaxStatementBytes: 64})
	e.Close()

	recs := records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	stmt, _ := recs[0]["statement"].(string)
	if len(stmt) > 64 {
		t.Errorf("statement is %d bytes, want at most 64", len(stmt))
	}
	if recs[0]["truncated"] != true {
		t.Errorf("truncated = %v, want true", recs[0]["truncated"])
	}
}

func TestEmitter_DropsWhenFull(t *testing.T) {
	// A logger that blocks lets the queue fill deterministically.
	release := make(chan struct{})
	logger := slog.New(slog.NewJSONHandler(blockingWriter{release}, nil))

	var dropped int64
	e := NewEmitter(logger, 1, Counters{
		Dropped: func(_ context.Context, n int64, _ string) { dropped += n },
	})

	for i := 0; i < 50; i++ {
		e.Log(&Event{Mode: ModePostgres, Level: LevelMetadata, RawStatement: "SELECT 1"})
	}
	close(release)
	e.Close()

	if e.Dropped() == 0 {
		t.Error("expected events to be dropped once the queue filled")
	}
	if dropped != e.Dropped() {
		t.Errorf("counter saw %d drops, emitter recorded %d", dropped, e.Dropped())
	}
	if e.Dropped()+e.Emitted() != 50 {
		t.Errorf("emitted %d + dropped %d != 50", e.Emitted(), e.Dropped())
	}
}

type blockingWriter struct{ release chan struct{} }

func (b blockingWriter) Write(p []byte) (int, error) {
	<-b.release
	return len(p), nil
}

// Log must stay safe after Close: connections can still be draining when
// shutdown begins, and a logging call must never take a connection down.
func TestEmitter_LogAfterCloseIsSafe(t *testing.T) {
	logger, _ := captureLogger(t)
	e := NewEmitter(logger, 4, Counters{})
	e.Close()

	e.Log(&Event{Mode: ModePostgres, Level: LevelMetadata, RawStatement: "SELECT 1"})

	if e.Dropped() != 1 {
		t.Errorf("dropped = %d, want 1", e.Dropped())
	}
}

func TestEmitter_NilIsInert(t *testing.T) {
	var e *Emitter
	e.Log(&Event{Level: LevelFull, RawStatement: "SELECT 1"})
	e.Close()
	if e.Dropped() != 0 || e.Emitted() != 0 {
		t.Error("nil emitter should report nothing")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		max     int
		want    string
		wantCut bool
	}{
		{"under limit", "abc", 10, "abc", false},
		{"at limit", "abcde", 5, "abcde", false},
		{"over limit", "abcdefgh", 4, "abcd", true},
		{"no limit", "abcdefgh", 0, "abcdefgh", false},
		{"does not split a rune", "aé", 2, "a", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, cut := truncate(tt.in, tt.max)
			if got != tt.want || cut != tt.wantCut {
				t.Errorf("truncate(%q, %d) = (%q, %v), want (%q, %v)", tt.in, tt.max, got, cut, tt.want, tt.wantCut)
			}
		})
	}
}
