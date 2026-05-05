package mongowire

import (
	"crypto/hmac"
	"encoding/base64"
	"testing"
)

func TestSCRAMRoundTrip(t *testing.T) {
	// Perform a full SCRAM-SHA-256 round-trip between SCRAMClient and
	// the server-side verification logic (same code path as readAndCompleteSASL).
	password := DummyPassword
	username := "testuser"

	// Client side: generate client-first-message.
	sc := NewSCRAMClient(username, password)
	clientFirst := sc.ClientFirstMessage()

	if clientFirst == "" {
		t.Fatal("empty client-first-message")
	}
	if nonce, user := parseClientFirst(clientFirst); nonce == "" || user != username {
		t.Fatalf("parseClientFirst: nonce=%q user=%q", nonce, user)
	}

	// Server side: generate server-first-message.
	srv := NewSCRAMServer()
	clientNonce, _ := parseClientFirst(clientFirst)
	serverFirst := srv.buildServerFirst(clientNonce)

	if serverFirst == "" {
		t.Fatal("empty server-first-message")
	}

	// Client side: generate client-final-message.
	clientFinal, err := sc.ClientFinalMessage(serverFirst)
	if err != nil {
		t.Fatalf("ClientFinalMessage: %v", err)
	}

	// Server side: verify client proof.
	clientFinalWithoutProof, proof, err := parseClientFinal(clientFinal)
	if err != nil {
		t.Fatalf("parseClientFinal: %v", err)
	}

	clientFirstBare := clientFirst[3:] // skip "n,,"
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	saltedPassword := scramHi([]byte(password), srv.salt, srv.iterations)
	clientKey := scramHMAC(saltedPassword, []byte("Client Key"))
	storedKey := scramSHA256(clientKey)
	clientSignature := scramHMAC(storedKey, []byte(authMessage))
	expectedProof := scramXOR(clientKey, clientSignature)

	if !hmac.Equal(proof, expectedProof) {
		t.Fatal("client proof mismatch")
	}

	// Server side: compute server-final-message.
	serverKey := scramHMAC(saltedPassword, []byte("Server Key"))
	serverSignature := scramHMAC(serverKey, []byte(authMessage))
	serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSignature)

	// Client side: verify server signature.
	if err := sc.VerifyServerFinal(serverFinal); err != nil {
		t.Fatalf("VerifyServerFinal: %v", err)
	}
}

func TestSCRAMRoundTrip_WrongPassword(t *testing.T) {
	sc := NewSCRAMClient("user", "wrongpassword")
	clientFirst := sc.ClientFirstMessage()

	srv := NewSCRAMServer()
	clientNonce, _ := parseClientFirst(clientFirst)
	serverFirst := srv.buildServerFirst(clientNonce)

	clientFinal, err := sc.ClientFinalMessage(serverFirst)
	if err != nil {
		t.Fatalf("ClientFinalMessage: %v", err)
	}

	_, proof, _ := parseClientFinal(clientFinal)
	clientFirstBare := clientFirst[3:]
	clientFinalWithoutProof, _, _ := parseClientFinal(clientFinal)
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	// Verify against DummyPassword (the server's password).
	saltedPassword := scramHi([]byte(DummyPassword), srv.salt, srv.iterations)
	clientKey := scramHMAC(saltedPassword, []byte("Client Key"))
	storedKey := scramSHA256(clientKey)
	clientSignature := scramHMAC(storedKey, []byte(authMessage))
	expectedProof := scramXOR(clientKey, clientSignature)

	if hmac.Equal(proof, expectedProof) {
		t.Fatal("proof should NOT match with wrong password")
	}
}

func TestSCRAMClient_ServerNonceMismatch(t *testing.T) {
	sc := NewSCRAMClient("user", "pass")
	sc.ClientFirstMessage()

	// Server-first with a nonce that doesn't start with client nonce.
	_, err := sc.ClientFinalMessage("r=completelydifferentnonce,s=c2FsdA==,i=4096")
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
}

func TestSCRAMClient_VerifyServerFinal_Error(t *testing.T) {
	sc := NewSCRAMClient("user", "pass")
	if err := sc.VerifyServerFinal("e=some-error"); err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestSCRAMClient_VerifyServerFinal_BadFormat(t *testing.T) {
	sc := NewSCRAMClient("user", "pass")
	if err := sc.VerifyServerFinal("garbage"); err == nil {
		t.Fatal("expected error for bad format")
	}
}

func TestParseClientFirst(t *testing.T) {
	nonce, user := parseClientFirst("n,,n=testuser,r=abc123")
	if nonce != "abc123" {
		t.Errorf("nonce = %q, want abc123", nonce)
	}
	if user != "testuser" {
		t.Errorf("user = %q, want testuser", user)
	}
}

func TestParseClientFirst_NoGS2Header(t *testing.T) {
	nonce, user := parseClientFirst("n=user,r=nonce123")
	if nonce != "nonce123" {
		t.Errorf("nonce = %q, want nonce123", nonce)
	}
	if user != "user" {
		t.Errorf("user = %q, want user", user)
	}
}

func TestParseClientFinal_NoProof(t *testing.T) {
	_, _, err := parseClientFinal("c=biws,r=nonce")
	if err == nil {
		t.Fatal("expected error for missing proof")
	}
}

func TestSaslPrep(t *testing.T) {
	got := saslPrep("user=name,test")
	want := "user=3Dname=2Ctest"
	if got != want {
		t.Errorf("saslPrep = %q, want %q", got, want)
	}
}
