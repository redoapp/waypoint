package delegation

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadPrefaceFragmentedAndPreservesPostgresBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var frame bytes.Buffer
	if err := WritePreface(&frame, "signed.jwt"); err != nil {
		t.Fatal(err)
	}
	postgres := []byte{0, 0, 0, 8, 4, 210, 22, 47}
	combined := append(frame.Bytes(), postgres...)
	go func() {
		for _, b := range combined {
			_, _ = client.Write([]byte{b})
		}
	}()

	credential, err := ReadPreface(server, time.Second, DefaultMaxCredentialSize)
	if err != nil {
		t.Fatal(err)
	}
	if credential != "signed.jwt" {
		t.Fatalf("credential = %q", credential)
	}
	remaining := make([]byte, len(postgres))
	if _, err := io.ReadFull(server, remaining); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remaining, postgres) {
		t.Fatalf("remaining bytes = %v, want %v", remaining, postgres)
	}
}

func TestReadPrefaceRejectsMalformedFrames(t *testing.T) {
	header := func(magic string, version byte, length uint32, body string) []byte {
		frame := make([]byte, 9+len(body))
		copy(frame, magic)
		frame[4] = version
		binary.BigEndian.PutUint32(frame[5:9], length)
		copy(frame[9:], body)
		return frame
	}
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "truncated header", data: []byte("WPDG"), want: "header"},
		{name: "wrong magic", data: header("NOPE", 1, 1, "x"), want: "identifier"},
		{name: "unknown version", data: header("WPDG", 2, 1, "x"), want: "version"},
		{name: "missing credential", data: header("WPDG", 1, 0, ""), want: "missing"},
		{name: "oversized", data: header("WPDG", 1, DefaultMaxCredentialSize+1, ""), want: "exceeds"},
		{name: "truncated credential", data: header("WPDG", 1, 4, "x"), want: "credential"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			go func() {
				_, _ = client.Write(tt.data)
				_ = client.Close()
			}()
			_, err := ReadPreface(server, time.Second, DefaultMaxCredentialSize)
			_ = server.Close()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestReadPrefaceTimesOut(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	start := time.Now()
	_, err := ReadPreface(server, 20*time.Millisecond, DefaultMaxCredentialSize)
	if err == nil {
		t.Fatal("missing preface did not time out")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("preface timeout took %s", elapsed)
	}
}

type shortWriter struct {
	bytes.Buffer
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 2 {
		p = p[:2]
	}
	return w.Buffer.Write(p)
}

func TestWritePrefaceCompletesShortWrites(t *testing.T) {
	var got shortWriter
	if err := WritePreface(&got, "credential"); err != nil {
		t.Fatal(err)
	}
	if got.Len() != 9+len("credential") {
		t.Fatalf("frame length = %d", got.Len())
	}
}
