package querylog

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// A connection that dies mid-message must still hand every byte it did
// receive to the caller. The taps sit inside restrict.Relay, so swallowing a
// partial message would both truncate the peer's stream and lose bytes from
// the accounting that enforces bandwidth limits — and an abrupt client
// disconnect is an ordinary event, not an exotic one.
var zeroTime time.Time

func TestFramer_TruncatedStreamLosesNoBytes(t *testing.T) {
	full := encodeAll(t,
		&pgproto3.Query{String: "SELECT * FROM orders WHERE id = 1"},
		&pgproto3.Query{String: "SELECT * FROM users"},
	)

	tests := []struct {
		name string
		keep int
	}{
		{"cut mid-header", 3},
		{"cut just after a header", 5},
		{"cut mid-body", 12},
		{"cut between messages", len(full) - 10},
		{"single byte", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			truncated := full[:tt.keep]

			s, _ := newTestSession(t, LevelMetadata)
			tap := s.ClientConn(newFakeConn(truncated))

			var got bytes.Buffer
			if _, err := io.Copy(&got, tap); err != nil {
				t.Fatalf("copy: %v", err)
			}

			if !bytes.Equal(got.Bytes(), truncated) {
				t.Errorf("truncated stream corrupted: got %d bytes, want %d",
					got.Len(), len(truncated))
			}
		})
	}
}

// Reading into a zero-length buffer must not consume from the connection.
func TestFramer_EmptyReadConsumesNothing(t *testing.T) {
	stream := encodeAll(t, &pgproto3.Query{String: "SELECT 1"})

	s, _ := newTestSession(t, LevelMetadata)
	tap := s.ClientConn(newFakeConn(stream))

	n, err := tap.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}

	var got bytes.Buffer
	if _, err := io.Copy(&got, tap); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if !bytes.Equal(got.Bytes(), stream) {
		t.Error("a zero-length read consumed bytes from the connection")
	}
}

// A header the framer cannot make sense of is passed through rather than
// dropped: better to let the peer decide than to swallow bytes.
func TestFramer_MalformedHeaderPassesThrough(t *testing.T) {
	// A Postgres length field below the 4-byte minimum is not a valid frame.
	malformed := []byte{'Q', 0, 0, 0, 1, 'j', 'u', 'n', 'k'}

	s, _ := newTestSession(t, LevelMetadata)
	tap := s.ClientConn(newFakeConn(malformed))

	var got bytes.Buffer
	if _, err := io.Copy(&got, tap); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if !bytes.Equal(got.Bytes(), malformed) {
		t.Errorf("malformed stream corrupted: got %q, want %q", got.Bytes(), malformed)
	}
}

// The wrapper must behave like the connection it wraps for everything it does
// not intercept.
func TestFramer_DelegatesConnBehavior(t *testing.T) {
	underlying := newFakeConn(nil)

	s, _ := newTestSession(t, LevelMetadata)
	tap := s.ClientConn(underlying)

	if n, err := tap.Write([]byte("hello")); n != 5 || err != nil {
		t.Errorf("Write = (%d, %v), want (5, nil)", n, err)
	}
	if got := underlying.w.String(); got != "hello" {
		t.Errorf("underlying conn received %q, want \"hello\"", got)
	}

	if tap.LocalAddr() != underlying.LocalAddr() {
		t.Error("LocalAddr is not delegated")
	}
	if tap.RemoteAddr() != underlying.RemoteAddr() {
		t.Error("RemoteAddr is not delegated")
	}
	for name, err := range map[string]error{
		"SetDeadline":      tap.SetDeadline(zeroTime),
		"SetReadDeadline":  tap.SetReadDeadline(zeroTime),
		"SetWriteDeadline": tap.SetWriteDeadline(zeroTime),
		"Close":            tap.Close(),
	} {
		if err != nil {
			t.Errorf("%s returned %v, want nil", name, err)
		}
	}
}
