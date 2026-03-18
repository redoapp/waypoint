package pgwire

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestHandleUpstreamAuth_AuthOk(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()

	go func() {
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.AuthenticationOk{})
		be.Flush()
	}()

	fe, err := HandleUpstreamAuth(upstream, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	if fe == nil {
		t.Fatal("expected non-nil frontend")
	}
}

func TestHandleUpstreamAuth_CleartextPassword(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()

	go func() {
		// Use Backend for sending server messages and receiving client messages.
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.AuthenticationCleartextPassword{})
		be.Flush()

		// Read password response using Backend.Receive (reads FrontendMessage).
		msg, err := be.Receive()
		if err != nil {
			t.Errorf("receive password: %v", err)
			return
		}
		pm, ok := msg.(*pgproto3.PasswordMessage)
		if !ok {
			t.Errorf("expected PasswordMessage, got %T", msg)
			return
		}
		if pm.Password != "testpass" {
			t.Errorf("password = %q, want testpass", pm.Password)
		}

		// Send AuthOk.
		be.Send(&pgproto3.AuthenticationOk{})
		be.Flush()
	}()

	fe, err := HandleUpstreamAuth(upstream, "user", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	if fe == nil {
		t.Fatal("expected non-nil frontend")
	}
}

func TestHandleUpstreamAuth_MD5Password(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()

	salt := [4]byte{0x01, 0x02, 0x03, 0x04}

	go func() {
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.AuthenticationMD5Password{Salt: salt})
		be.Flush()

		// Read password response.
		msg, err := be.Receive()
		if err != nil {
			t.Errorf("receive password: %v", err)
			return
		}
		pm, ok := msg.(*pgproto3.PasswordMessage)
		if !ok {
			t.Errorf("expected PasswordMessage, got %T", msg)
			return
		}
		expected := md5Hash("testpass", "testuser", salt)
		if pm.Password != expected {
			t.Errorf("md5 password = %q, want %q", pm.Password, expected)
		}

		// Send AuthOk.
		be.Send(&pgproto3.AuthenticationOk{})
		be.Flush()
	}()

	fe, err := HandleUpstreamAuth(upstream, "testuser", "testpass")
	if err != nil {
		t.Fatal(err)
	}
	if fe == nil {
		t.Fatal("expected non-nil frontend")
	}
}

func TestHandleUpstreamAuth_SCRAM(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()

	password := "scrampassword"
	serverSalt := []byte("serversaltvalue!")

	go func() {
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
		be.Flush()

		// Tell backend to expect SASL messages.
		be.SetAuthType(pgproto3.AuthTypeSASL)

		// Read SASLInitialResponse.
		msg, err := be.Receive()
		if err != nil {
			t.Errorf("receive SASL initial: %v", err)
			return
		}
		saslInit, ok := msg.(*pgproto3.SASLInitialResponse)
		if !ok {
			t.Errorf("expected SASLInitialResponse, got %T", msg)
			return
		}

		// Parse client-first to get nonce.
		clientFirst := string(saslInit.Data)
		// Format: "n,,n=user,r=<nonce>"
		parts := strings.Split(clientFirst[3:], ",") // skip "n,,"
		var clientNonce string
		for _, p := range parts {
			if strings.HasPrefix(p, "r=") {
				clientNonce = p[2:]
			}
		}

		serverNonce := clientNonce + "serversuffix"
		encodedSalt := base64.StdEncoding.EncodeToString(serverSalt)
		serverFirst := "r=" + serverNonce + ",s=" + encodedSalt + ",i=4096"

		// Send SASLContinue.
		be.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
		be.Flush()

		// Tell backend to expect SASLResponse next.
		be.SetAuthType(pgproto3.AuthTypeSASLContinue)

		// Read SASLResponse (client-final).
		msg, err = be.Receive()
		if err != nil {
			t.Errorf("receive SASL response: %v", err)
			return
		}
		_, ok = msg.(*pgproto3.SASLResponse)
		if !ok {
			t.Errorf("expected SASLResponse, got %T", msg)
			return
		}

		// Compute server signature.
		clientFirstBare := clientFirst[3:]
		channelBinding := "c=biws"
		clientFinalWithoutProof := channelBinding + ",r=" + serverNonce
		authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

		saltedPassword := hi([]byte(password), serverSalt, 4096)
		serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
		serverSig := hmacSHA256(serverKey, []byte(authMessage))

		serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSig)

		// Send SASLFinal.
		be.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte(serverFinal)})
		be.Flush()

		// Send AuthOk.
		be.Send(&pgproto3.AuthenticationOk{})
		be.Flush()
	}()

	fe, err := HandleUpstreamAuth(upstream, "scramuser", password)
	if err != nil {
		t.Fatal(err)
	}
	if fe == nil {
		t.Fatal("expected non-nil frontend")
	}
}

func TestHandleUpstreamAuth_ErrorResponse(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()

	go func() {
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "28P01",
			Message:  "password authentication failed",
		})
		be.Flush()
	}()

	_, err := HandleUpstreamAuth(upstream, "user", "wrongpass")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "password authentication failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHandleUpstreamAuth_UnsupportedSASLMechanism(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	defer upstream.Close()
	defer upstreamRemote.Close()

	go func() {
		be := pgproto3.NewBackend(upstreamRemote, upstreamRemote)
		be.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-512"}})
		be.Flush()
	}()

	_, err := HandleUpstreamAuth(upstream, "user", "pass")
	if err == nil {
		t.Fatal("expected error for unsupported SASL mechanism")
	}
	if !strings.Contains(err.Error(), "SCRAM-SHA-256") {
		t.Errorf("error should mention SCRAM-SHA-256, got: %v", err)
	}
}

func TestHandleUpstreamAuth_ConnectionClosed(t *testing.T) {
	upstream, upstreamRemote := net.Pipe()
	defer upstream.Close()

	upstreamRemote.Close() // Close immediately.

	_, err := HandleUpstreamAuth(upstream, "user", "pass")
	if err == nil {
		t.Fatal("expected error for closed connection")
	}
}

func TestParseServerFinal_InvalidBase64(t *testing.T) {
	_, err := parseServerFinal("v=not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestGenerateNonce_Uniqueness(t *testing.T) {
	n1 := generateNonce()
	n2 := generateNonce()
	if n1 == n2 {
		t.Fatal("expected unique nonces")
	}
}

func TestSaslPrepPassword(t *testing.T) {
	if got := saslPrepPassword("hello"); got != "hello" {
		t.Errorf("expected passthrough, got %q", got)
	}
}

func TestHmacEqual(t *testing.T) {
	a := sha256Hash([]byte("test"))
	b := sha256Hash([]byte("test"))
	c := sha256Hash([]byte("other"))

	if !hmacEqual(a, b) {
		t.Error("expected equal")
	}
	if hmacEqual(a, c) {
		t.Error("expected not equal")
	}
}

func TestSha256Hash_Length(t *testing.T) {
	result := sha256Hash([]byte("data"))
	if len(result) != sha256.Size {
		t.Errorf("expected %d bytes, got %d", sha256.Size, len(result))
	}
}
