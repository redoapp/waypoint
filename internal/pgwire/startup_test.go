package pgwire

import (
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
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
	msg, err := ReadStartupMessage(server)
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

	msg, err := ReadStartupMessage(server)
	if err != nil {
		t.Fatal(err)
	}

	if msg.Parameters["user"] != "ssluser" {
		t.Errorf("user = %q, want ssluser", msg.Parameters["user"])
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

	_, err := ReadStartupMessage(server)
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

	msg, err := ReadStartupMessage(server)
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
		done <- ForwardPostAuth(upstream, client)
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
