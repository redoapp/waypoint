package pgwire

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/redoapp/waypoint/internal/config"
)

// rawStartup encodes a StartupMessage with an arbitrary protocol version, which
// pgproto3 cannot do for versions other than 3.0 on the decode side.
func rawStartup(version uint32, params ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, version)
	for _, p := range params {
		body = append(body, p...)
		body = append(body, 0)
	}
	body = append(body, 0)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body)+4)), body...)
}

func rawCancelRequest(keyLen int) []byte {
	body := binary.BigEndian.AppendUint32(nil, cancelRequestCode)
	body = binary.BigEndian.AppendUint32(body, 4242) // backend PID
	body = append(body, make([]byte, keyLen)...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body)+4)), body...)
}

// readNegotiateProtocolVersion reads one NegotiateProtocolVersion message and
// returns the full protocol version it carries plus the rejected options.
func readNegotiateProtocolVersion(t *testing.T, r io.Reader) (uint32, []string) {
	t.Helper()
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatalf("read message header: %v", err)
	}
	if header[0] != 'v' {
		t.Fatalf("message type = %q, want 'v' (NegotiateProtocolVersion)", header[0])
	}
	body := make([]byte, binary.BigEndian.Uint32(header[1:])-4)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("read message body: %v", err)
	}
	version := binary.BigEndian.Uint32(body[0:4])
	count := int(binary.BigEndian.Uint32(body[4:8]))
	rest := body[8:]
	var opts []string
	for i := 0; i < count; i++ {
		end := 0
		for end < len(rest) && rest[end] != 0 {
			end++
		}
		if end == len(rest) {
			t.Fatalf("option %d is not NUL-terminated", i)
		}
		opts = append(opts, string(rest[:end]))
		rest = rest[end+1:]
	}
	if len(rest) != 0 {
		t.Fatalf("%d trailing bytes after options", len(rest))
	}
	return version, opts
}

type startupResult struct {
	conn net.Conn
	msg  *pgproto3.StartupMessage
	err  error
}

func readStartupAsync(conn net.Conn, mode config.PostgresTLSMode, tlsConfig *tls.Config) <-chan startupResult {
	ch := make(chan startupResult, 1)
	go func() {
		c, msg, err := ReadStartupMessage(conn, mode, tlsConfig)
		ch <- startupResult{c, msg, err}
	}()
	return ch
}

func TestReadStartupMessage_Protocol32Negotiated(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := readStartupAsync(server, config.PostgresTLSOff, nil)
	if _, err := client.Write(rawStartup(3<<16|2, "user", "alice", "database", "app")); err != nil {
		t.Fatal(err)
	}

	version, opts := readNegotiateProtocolVersion(t, client)
	if version != pgproto3.ProtocolVersionNumber || len(opts) != 0 {
		t.Fatalf("NegotiateProtocolVersion = (%d, %v), want (%d, [])", version, opts, pgproto3.ProtocolVersionNumber)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("ReadStartupMessage: %v", res.err)
	}
	if res.msg.ProtocolVersion != pgproto3.ProtocolVersionNumber {
		t.Errorf("ProtocolVersion = %d, want %d (session runs at 3.0)", res.msg.ProtocolVersion, pgproto3.ProtocolVersionNumber)
	}
	want := map[string]string{"user": "alice", "database": "app"}
	if !reflect.DeepEqual(res.msg.Parameters, want) {
		t.Errorf("Parameters = %v, want %v", res.msg.Parameters, want)
	}
}

func TestReadStartupMessage_ProtocolOptionsRejectedAndStripped(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := readStartupAsync(server, config.PostgresTLSOff, nil)
	if _, err := client.Write(rawStartup(pgproto3.ProtocolVersionNumber,
		"user", "alice",
		"_pq_.report_parameters", "search_path",
		"database", "app",
		"_pq_.compression", "on",
	)); err != nil {
		t.Fatal(err)
	}

	version, opts := readNegotiateProtocolVersion(t, client)
	if version != pgproto3.ProtocolVersionNumber {
		t.Errorf("negotiated version = %d, want %d (3.0)", version, pgproto3.ProtocolVersionNumber)
	}
	if want := []string{"_pq_.compression", "_pq_.report_parameters"}; !reflect.DeepEqual(opts, want) {
		t.Errorf("unrecognized options = %v, want %v", opts, want)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("ReadStartupMessage: %v", res.err)
	}
	want := map[string]string{"user": "alice", "database": "app"}
	if !reflect.DeepEqual(res.msg.Parameters, want) {
		t.Errorf("Parameters = %v, want %v (protocol options must not reach the backend)", res.msg.Parameters, want)
	}
}

func TestReadStartupMessage_Protocol30NoNegotiation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := readStartupAsync(server, config.PostgresTLSOff, nil)
	if _, err := client.Write(rawStartup(pgproto3.ProtocolVersionNumber, "user", "alice")); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("ReadStartupMessage: %v", res.err)
	}

	// The next thing the client sees must be the server's own message, not a
	// NegotiateProtocolVersion.
	go SendAuthOK(server)
	first := make([]byte, 1)
	if _, err := io.ReadFull(client, first); err != nil {
		t.Fatal(err)
	}
	if first[0] != 'R' {
		t.Fatalf("first message type = %q, want 'R'", first[0])
	}
}

func TestReadStartupMessage_Protocol32OverTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := readStartupAsync(server, config.PostgresTLSRequire, mustServerTLSConfig(t))

	if _, err := client.Write([]byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(client, resp); err != nil || resp[0] != 'S' {
		t.Fatalf("SSL response = %q, %v; want 'S'", resp, err)
	}
	tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsClient.Write(rawStartup(3<<16|2, "user", "alice")); err != nil {
		t.Fatal(err)
	}
	if version, opts := readNegotiateProtocolVersion(t, tlsClient); version != pgproto3.ProtocolVersionNumber || len(opts) != 0 {
		t.Fatalf("NegotiateProtocolVersion = (%d, %v), want (%d, [])", version, opts, pgproto3.ProtocolVersionNumber)
	}
	if res := <-done; res.err != nil {
		t.Fatalf("ReadStartupMessage: %v", res.err)
	}
}

func TestReadStartupMessage_UnsupportedMajorVersion(t *testing.T) {
	for _, version := range []uint32{2 << 16, 4 << 16} {
		client, server := net.Pipe()
		done := readStartupAsync(server, config.PostgresTLSOff, nil)
		if _, err := client.Write(rawStartup(version, "user", "alice")); err != nil {
			t.Fatal(err)
		}
		res := <-done
		if !errors.Is(res.err, ErrUnsupportedProtocol) {
			t.Errorf("version %d.%d: err = %v, want ErrUnsupportedProtocol", version>>16, version&0xffff, res.err)
		}
		client.Close()
		server.Close()
	}
}

func TestReadStartupMessage_Protocol32CancelRequest(t *testing.T) {
	for _, keyLen := range []int{4, 32, maxCancelKeyLength} {
		client, server := net.Pipe()
		done := readStartupAsync(server, config.PostgresTLSOff, nil)
		if _, err := client.Write(rawCancelRequest(keyLen)); err != nil {
			t.Fatal(err)
		}
		if res := <-done; !errors.Is(res.err, ErrCancelRequest) {
			t.Errorf("key length %d: err = %v, want ErrCancelRequest", keyLen, res.err)
		}
		client.Close()
		server.Close()
	}
}

func TestReadStartupMessage_OversizedCancelKeyNotTreatedAsCancel(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := readStartupAsync(server, config.PostgresTLSOff, nil)
	if _, err := client.Write(rawCancelRequest(maxCancelKeyLength + 1)); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if res.err == nil || errors.Is(res.err, ErrCancelRequest) {
		t.Fatalf("err = %v, want a non-cancel error for an oversized key", res.err)
	}
}
