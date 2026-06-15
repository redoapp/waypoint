package pgwire

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/redoapp/waypoint/internal/config"
)

func TestReadWriteStartupMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Write a startup message from the "client".
	go func() {
		if err := WriteStartupMessage(client, "testuser", "testdb", map[string]string{
			"application_name": "waypoint-test",
		}); err != nil {
			t.Errorf("write startup: %v", err)
		}
	}()

	// Read it from the "server" side.
	_, msg, err := ReadStartupMessage(server, config.PostgresTLSOff, nil)
	if err != nil {
		t.Fatal(err)
	}

	if msg.Parameters["user"] != "testuser" {
		t.Errorf("user = %q, want testuser", msg.Parameters["user"])
	}
	if msg.Parameters["database"] != "testdb" {
		t.Errorf("database = %q, want testdb", msg.Parameters["database"])
	}
	if msg.Parameters["application_name"] != "waypoint-test" {
		t.Errorf("application_name = %q, want waypoint-test", msg.Parameters["application_name"])
	}
}

func TestReadStartupMessage_SSLDenied(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Send SSLRequest first (8 bytes: length=8, version=80877103).
		sslReq := []byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F}
		client.Write(sslReq)

		// Read the 'N' denial.
		buf := make([]byte, 1)
		n, err := client.Read(buf)
		if err != nil || n != 1 || buf[0] != 'N' {
			t.Errorf("expected 'N', got %v (err: %v)", buf[:n], err)
			return
		}

		// Now send a real startup message.
		WriteStartupMessage(client, "ssluser", "ssldb", nil)
	}()

	_, msg, err := ReadStartupMessage(server, config.PostgresTLSOff, nil)
	if err != nil {
		t.Fatal(err)
	}

	if msg.Parameters["user"] != "ssluser" {
		t.Errorf("user = %q, want ssluser", msg.Parameters["user"])
	}
}

func TestReadStartupMessage_GSSEncDenied(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Send GSSENCRequest (8 bytes: length=8, version=80877104 = 0x04D21630).
		client.Write([]byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x30})

		// Read the 'N' denial.
		buf := make([]byte, 1)
		n, err := client.Read(buf)
		if err != nil || n != 1 || buf[0] != 'N' {
			t.Errorf("expected 'N', got %v (err: %v)", buf[:n], err)
			return
		}

		// Then send a real startup message on the same connection.
		WriteStartupMessage(client, "gssuser", "gssdb", nil)
	}()

	_, msg, err := ReadStartupMessage(server, config.PostgresTLSOff, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Parameters["user"] != "gssuser" {
		t.Errorf("user = %q, want gssuser", msg.Parameters["user"])
	}
}

func TestReadStartupMessage_CancelRequest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// CancelRequest: length=16, code=80877102 (0x04D2162E), pid=1, secret=2.
		client.Write([]byte{0, 0, 0, 16, 0x04, 0xD2, 0x16, 0x2E, 0, 0, 0, 1, 0, 0, 0, 2})
	}()

	_, _, err := ReadStartupMessage(server, config.PostgresTLSOff, nil)
	if !errors.Is(err, ErrCancelRequest) {
		t.Fatalf("expected ErrCancelRequest, got %v", err)
	}
}

func TestReadStartupMessage_EOFBeforeStartup(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	// Client closes without sending anything.
	go client.Close()

	_, _, err := ReadStartupMessage(server, config.PostgresTLSOff, nil)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected error wrapping io.EOF, got %v", err)
	}
}

func TestReadStartupMessage_InvalidLength(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		// Length = 2, which is less than minimum 4.
		client.Write([]byte{0, 0, 0, 2})
		client.Close()
	}()

	_, _, err := ReadStartupMessage(server, config.PostgresTLSOff, nil)
	if err == nil {
		t.Fatal("expected error for invalid length")
	}
}

func TestWriteStartupMessage_SkipsDuplicateUserDB(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Passing "user" and "database" in extra params should not duplicate.
		WriteStartupMessage(client, "realuser", "realdb", map[string]string{
			"user":     "ignored",
			"database": "ignored",
			"extra":    "kept",
		})
	}()

	_, msg, err := ReadStartupMessage(server, config.PostgresTLSOff, nil)
	if err != nil {
		t.Fatal(err)
	}

	if msg.Parameters["user"] != "realuser" {
		t.Errorf("user = %q, want realuser", msg.Parameters["user"])
	}
	if msg.Parameters["database"] != "realdb" {
		t.Errorf("database = %q, want realdb", msg.Parameters["database"])
	}
	if msg.Parameters["extra"] != "kept" {
		t.Errorf("extra = %q, want kept", msg.Parameters["extra"])
	}
}

func TestSendAuthOK(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		SendAuthOK(server)
	}()

	fe := pgproto3.NewFrontend(client, client)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := msg.(*pgproto3.AuthenticationOk); !ok {
		t.Fatalf("expected AuthenticationOk, got %T", msg)
	}
}

func TestSendErrorResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		SendErrorResponse(server, "FATAL", "28000", "test error message")
	}()

	fe := pgproto3.NewFrontend(client, client)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}

	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if errResp.Severity != "FATAL" {
		t.Errorf("severity = %q", errResp.Severity)
	}
	if errResp.Code != "28000" {
		t.Errorf("code = %q", errResp.Code)
	}
	if errResp.Message != "test error message" {
		t.Errorf("message = %q", errResp.Message)
	}
}

func TestReadStartupMessage_OversizedLength(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		// Length = 10241, which exceeds the 10240 limit.
		client.Write([]byte{0, 0, 0x28, 0x01}) // 10241 in big-endian
		client.Close()
	}()

	_, _, err := ReadStartupMessage(server, config.PostgresTLSOff, nil)
	if err == nil {
		t.Fatal("expected error for oversized length")
	}
}

func TestReadStartupMessage_TLSOptionalAcceptsSSL(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverTLS := mustServerTLSConfig(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		sslReq := []byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F}
		if _, err := client.Write(sslReq); err != nil {
			t.Errorf("write ssl request: %v", err)
			return
		}

		buf := make([]byte, 1)
		if _, err := client.Read(buf); err != nil {
			t.Errorf("read ssl response: %v", err)
			return
		}
		if buf[0] != 'S' {
			t.Errorf("expected 'S', got %q", buf[0])
			return
		}

		tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
		if err := tlsClient.Handshake(); err != nil {
			t.Errorf("client handshake: %v", err)
			return
		}
		if err := WriteStartupMessage(tlsClient, "ssluser", "ssldb", nil); err != nil {
			t.Errorf("write startup over tls: %v", err)
		}
	}()

	gotConn, msg, err := ReadStartupMessage(server, config.PostgresTLSOptional, serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer gotConn.Close()
	<-done

	if _, ok := gotConn.(*tls.Conn); !ok {
		t.Fatalf("expected TLS-wrapped connection, got %T", gotConn)
	}
	if msg.Parameters["user"] != "ssluser" {
		t.Errorf("user = %q, want ssluser", msg.Parameters["user"])
	}
}

func TestReadStartupMessage_TLSRequireRejectsPlaintext(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		if err := WriteStartupMessage(client, "plainuser", "plaindb", nil); err != nil {
			t.Errorf("write startup: %v", err)
		}
	}()

	_, _, err := ReadStartupMessage(server, config.PostgresTLSRequire, mustServerTLSConfig(t))
	if !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("expected ErrTLSRequired, got %v", err)
	}
}

func TestReadStartupMessage_TLSOptionalAllowsPlaintext(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		if err := WriteStartupMessage(client, "plainuser", "plaindb", nil); err != nil {
			t.Errorf("write startup: %v", err)
		}
	}()

	gotConn, msg, err := ReadStartupMessage(server, config.PostgresTLSOptional, mustServerTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if gotConn == nil {
		t.Fatal("expected connection")
	}
	if _, ok := gotConn.(*tls.Conn); ok {
		t.Fatal("expected plaintext connection")
	}
	if msg.Parameters["user"] != "plainuser" {
		t.Errorf("user = %q, want plainuser", msg.Parameters["user"])
	}
}

func TestForwardPostAuth_ErrorResponse(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	client, clientRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()
	defer client.Close()
	defer clientRemote.Close()

	go func() {
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "28000",
			Message:  "auth failed",
		})
		be.Flush()
	}()

	err := ForwardPostAuth(pgproto3.NewFrontend(upstream, upstream), client)
	if err == nil {
		t.Fatal("expected error from ErrorResponse")
	}
	if !strings.Contains(err.Error(), "auth failed") {
		t.Errorf("error should contain message, got: %v", err)
	}
}

func TestForwardPostAuth_UnknownMessageForwarded(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	client, clientRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()
	defer client.Close()
	defer clientRemote.Close()

	// Upstream sends a NoticeResponse (unknown to the switch) then ReadyForQuery.
	go func() {
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.NoticeResponse{
			Severity: "WARNING",
			Message:  "just a notice",
		})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		be.Flush()
	}()

	done := make(chan error, 1)
	go func() {
		done <- ForwardPostAuth(pgproto3.NewFrontend(upstream, upstream), client)
	}()

	// Read from client side - should get the notice forwarded.
	fe := pgproto3.NewFrontend(clientRemote, clientRemote)

	msg1, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg1.(*pgproto3.NoticeResponse); !ok {
		t.Fatalf("expected NoticeResponse, got %T", msg1)
	}

	msg2, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg2.(*pgproto3.ReadyForQuery); !ok {
		t.Fatalf("expected ReadyForQuery, got %T", msg2)
	}

	if err := <-done; err != nil {
		t.Fatalf("ForwardPostAuth returned error: %v", err)
	}
}

func mustServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

func TestForwardPostAuth(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	client, clientRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()
	defer client.Close()
	defer clientRemote.Close()

	// Simulate upstream sending post-auth messages.
	go func() {
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
		be.Send(&pgproto3.BackendKeyData{ProcessID: 123, SecretKey: 456})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		be.Flush()
	}()

	// ForwardPostAuth should relay all to client.
	done := make(chan error, 1)
	go func() {
		done <- ForwardPostAuth(pgproto3.NewFrontend(upstream, upstream), client)
	}()

	// Read from client side.
	fe := pgproto3.NewFrontend(clientRemote, clientRemote)

	msg1, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	ps, ok := msg1.(*pgproto3.ParameterStatus)
	if !ok {
		t.Fatalf("expected ParameterStatus, got %T", msg1)
	}
	if ps.Name != "server_version" || ps.Value != "15.0" {
		t.Errorf("ParameterStatus = %v", ps)
	}

	msg2, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	bkd, ok := msg2.(*pgproto3.BackendKeyData)
	if !ok {
		t.Fatalf("expected BackendKeyData, got %T", msg2)
	}
	if bkd.ProcessID != 123 {
		t.Errorf("ProcessID = %d", bkd.ProcessID)
	}

	msg3, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	rfq, ok := msg3.(*pgproto3.ReadyForQuery)
	if !ok {
		t.Fatalf("expected ReadyForQuery, got %T", msg3)
	}
	if rfq.TxStatus != 'I' {
		t.Errorf("TxStatus = %c", rfq.TxStatus)
	}

	if err := <-done; err != nil {
		t.Fatalf("ForwardPostAuth returned error: %v", err)
	}
}
