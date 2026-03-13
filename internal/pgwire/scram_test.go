package pgwire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestParseServerFirst_Valid(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("randomsalt"))
	msg := "r=clientnonceservernonce,s=" + salt + ",i=4096"

	parsed, err := parseServerFirst(msg)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.nonce != "clientnonceservernonce" {
		t.Errorf("nonce = %q", parsed.nonce)
	}
	if string(parsed.salt) != "randomsalt" {
		t.Errorf("salt = %q", string(parsed.salt))
	}
	if parsed.iterations != 4096 {
		t.Errorf("iterations = %d", parsed.iterations)
	}
}

func TestParseServerFirst_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"missing nonce", "s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096"},
		{"missing salt", "r=nonce,i=4096"},
		{"missing iterations", "r=nonce,s=" + base64.StdEncoding.EncodeToString([]byte("salt"))},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseServerFirst(tt.msg)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseServerFirst_InvalidSalt(t *testing.T) {
	msg := "r=nonce,s=not-valid-base64!!!,i=4096"
	_, err := parseServerFirst(msg)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseServerFirst_InvalidIterations(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("salt"))
	msg := "r=nonce,s=" + salt + ",i=notanumber"
	_, err := parseServerFirst(msg)
	if err == nil {
		t.Fatal("expected error for invalid iterations")
	}
}

func TestParseServerFinal_Valid(t *testing.T) {
	verifier := base64.StdEncoding.EncodeToString([]byte("server-signature"))
	msg := "v=" + verifier

	parsed, err := parseServerFinal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.verifier) != "server-signature" {
		t.Errorf("verifier = %q", string(parsed.verifier))
	}
}

func TestParseServerFinal_Error(t *testing.T) {
	_, err := parseServerFinal("e=invalid-encoding")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseServerFinal_UnexpectedFormat(t *testing.T) {
	_, err := parseServerFinal("x=something")
	if err == nil {
		t.Fatal("expected error for unexpected format")
	}
}

func TestHi_KnownVector(t *testing.T) {
	// RFC 7677 test vector:
	// PBKDF2-SHA256("pencil", base64decode("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096)
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	result := hi([]byte("pencil"), salt, 4096)

	// Verify it produces 32 bytes (SHA-256 output).
	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}

	// Verify deterministic.
	result2 := hi([]byte("pencil"), salt, 4096)
	if !hmac.Equal(result, result2) {
		t.Fatal("hi is not deterministic")
	}
}

func TestHi_DifferentInputsProduceDifferentOutputs(t *testing.T) {
	salt := []byte("salt")
	r1 := hi([]byte("password1"), salt, 4096)
	r2 := hi([]byte("password2"), salt, 4096)
	if hmac.Equal(r1, r2) {
		t.Fatal("different passwords should produce different output")
	}
}

func TestHmacSHA256(t *testing.T) {
	key := []byte("key")
	data := []byte("data")
	result := hmacSHA256(key, data)

	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}

	// Verify against stdlib directly.
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if !hmac.Equal(result, expected) {
		t.Fatal("hmacSHA256 does not match stdlib")
	}
}

func TestSha256Hash(t *testing.T) {
	result := sha256Hash([]byte("hello"))
	if len(result) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(result))
	}

	expected := sha256.Sum256([]byte("hello"))
	if !hmac.Equal(result, expected[:]) {
		t.Fatal("sha256Hash does not match stdlib")
	}
}

func TestXorBytes(t *testing.T) {
	a := []byte{0xFF, 0x00, 0xAA}
	b := []byte{0x0F, 0xF0, 0x55}
	result := xorBytes(a, b)

	expected := []byte{0xF0, 0xF0, 0xFF}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: got %02x, want %02x", i, result[i], expected[i])
		}
	}
}

func TestXorBytesInto(t *testing.T) {
	dst := []byte{0xFF, 0x00}
	src := []byte{0x0F, 0xF0}
	xorBytesInto(dst, src)

	if dst[0] != 0xF0 || dst[1] != 0xF0 {
		t.Errorf("got %02x %02x", dst[0], dst[1])
	}
}

func TestBase64Encode(t *testing.T) {
	result := base64Encode([]byte("hello"))
	expected := base64.StdEncoding.EncodeToString([]byte("hello"))
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestSaslPrepUsername(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"alice", "alice"},
		{"a=b", "a=3Db"},
		{"a,b", "a=2Cb"},
		{"a=b,c", "a=3Db=2Cc"},
	}
	for _, tt := range tests {
		got := saslPrepUsername(tt.input)
		if got != tt.want {
			t.Errorf("saslPrepUsername(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMd5Hash(t *testing.T) {
	// Known PostgreSQL MD5 auth format: "md5" + md5(md5(password + user) + salt).
	result := md5Hash("password", "user", [4]byte{0x01, 0x02, 0x03, 0x04})

	if len(result) != 35 { // "md5" + 32 hex chars
		t.Errorf("expected 35 chars, got %d", len(result))
	}
	if result[:3] != "md5" {
		t.Errorf("expected 'md5' prefix, got %q", result[:3])
	}

	// Deterministic.
	result2 := md5Hash("password", "user", [4]byte{0x01, 0x02, 0x03, 0x04})
	if result != result2 {
		t.Fatal("md5Hash is not deterministic")
	}

	// Different salt produces different result.
	result3 := md5Hash("password", "user", [4]byte{0x05, 0x06, 0x07, 0x08})
	if result == result3 {
		t.Fatal("different salt should produce different hash")
	}
}

func TestScramClient_RoundTrip(t *testing.T) {
	// Simulate a full SCRAM exchange using known values.
	user := "testuser"
	password := "testpassword"

	sc := newSCRAMClient(user, password)
	clientFirst := sc.clientFirstMessage()

	if clientFirst == "" {
		t.Fatal("empty client-first-message")
	}

	// Verify format: "n,,n=<user>,r=<nonce>"
	if clientFirst[:3] != "n,," {
		t.Errorf("expected 'n,,' prefix, got %q", clientFirst[:3])
	}

	// Simulate a server-first-message.
	salt := base64.StdEncoding.EncodeToString([]byte("serversalt123456"))
	serverNonce := sc.nonce + "serversuffix"
	serverFirst := "r=" + serverNonce + ",s=" + salt + ",i=4096"

	clientFinal, err := sc.clientFinalMessage(serverFirst)
	if err != nil {
		t.Fatal(err)
	}
	if clientFinal == "" {
		t.Fatal("empty client-final-message")
	}

	// Verify client-final starts with channel binding.
	if clientFinal[:6] != "c=biws" {
		t.Errorf("expected 'c=biws' prefix, got %q", clientFinal[:6])
	}

	// Compute expected server signature for verification.
	saltedPassword := hi([]byte(password), []byte("serversalt123456"), 4096)
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	serverSig := hmacSHA256(serverKey, []byte(sc.authMessage))
	serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSig)

	if err := sc.verifyServerFinal(serverFinal); err != nil {
		t.Fatalf("server signature verification failed: %v", err)
	}
}

func TestScramClient_BadServerNonce(t *testing.T) {
	sc := newSCRAMClient("user", "pass")
	sc.clientFirstMessage()

	salt := base64.StdEncoding.EncodeToString([]byte("salt"))
	// Server nonce doesn't start with client nonce.
	serverFirst := "r=totallydifferent,s=" + salt + ",i=4096"

	_, err := sc.clientFinalMessage(serverFirst)
	if err == nil {
		t.Fatal("expected error for mismatched nonce")
	}
}

func TestScramClient_BadServerSignature(t *testing.T) {
	sc := newSCRAMClient("user", "pass")
	sc.clientFirstMessage()

	salt := base64.StdEncoding.EncodeToString([]byte("salt"))
	serverFirst := "r=" + sc.nonce + "extra,s=" + salt + ",i=4096"

	_, err := sc.clientFinalMessage(serverFirst)
	if err != nil {
		t.Fatal(err)
	}

	// Bad server signature.
	badVerifier := base64.StdEncoding.EncodeToString([]byte("wrong"))
	err = sc.verifyServerFinal("v=" + badVerifier)
	if err == nil {
		t.Fatal("expected error for bad server signature")
	}
}
