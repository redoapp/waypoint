package mongowire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// SCRAMClient performs SCRAM-SHA-256 authentication with a MongoDB backend.
type SCRAMClient struct {
	user, password string
	nonce          string
	clientFirst    string
	saltedPassword []byte
	authMessage    string
}

// NewSCRAMClient creates a SCRAM-SHA-256 client for backend authentication.
func NewSCRAMClient(user, password string) *SCRAMClient {
	return &SCRAMClient{user: user, password: password}
}

// ClientFirstMessage generates the SCRAM client-first-message.
func (s *SCRAMClient) ClientFirstMessage() string {
	s.nonce = generateSCRAMNonce()
	s.clientFirst = fmt.Sprintf("n,,n=%s,r=%s", saslPrep(s.user), s.nonce)
	return s.clientFirst
}

// ClientFinalMessage processes the server-first-message and generates the client-final-message.
func (s *SCRAMClient) ClientFinalMessage(serverFirst string) (string, error) {
	parsed, err := parseSCRAMServerFirst(serverFirst)
	if err != nil {
		return "", err
	}

	if len(parsed.nonce) <= len(s.nonce) || parsed.nonce[:len(s.nonce)] != s.nonce {
		return "", fmt.Errorf("server nonce does not start with client nonce")
	}

	s.saltedPassword = scramHi([]byte(s.password), parsed.salt, parsed.iterations)

	clientKey := scramHMAC(s.saltedPassword, []byte("Client Key"))
	storedKey := scramSHA256(clientKey)

	clientFirstBare := s.clientFirst[3:] // skip "n,,"
	channelBinding := "c=biws"
	clientFinalWithoutProof := fmt.Sprintf("%s,r=%s", channelBinding, parsed.nonce)
	s.authMessage = fmt.Sprintf("%s,%s,%s", clientFirstBare, serverFirst, clientFinalWithoutProof)

	clientSignature := scramHMAC(storedKey, []byte(s.authMessage))
	clientProof := scramXOR(clientKey, clientSignature)

	return fmt.Sprintf("%s,p=%s", clientFinalWithoutProof, base64.StdEncoding.EncodeToString(clientProof)), nil
}

// VerifyServerFinal verifies the server-final-message signature.
func (s *SCRAMClient) VerifyServerFinal(serverFinal string) error {
	if strings.HasPrefix(serverFinal, "e=") {
		return fmt.Errorf("SCRAM server error: %s", serverFinal[2:])
	}
	if !strings.HasPrefix(serverFinal, "v=") {
		return fmt.Errorf("unexpected server-final format: %q", serverFinal)
	}

	verifier, err := base64.StdEncoding.DecodeString(serverFinal[2:])
	if err != nil {
		return fmt.Errorf("decode verifier: %w", err)
	}

	serverKey := scramHMAC(s.saltedPassword, []byte("Server Key"))
	expected := scramHMAC(serverKey, []byte(s.authMessage))

	if !hmac.Equal(verifier, expected) {
		return fmt.Errorf("server signature mismatch")
	}
	return nil
}

// AuthenticateBackend performs the full SCRAM-SHA-256 exchange with the backend
// after the hello handshake. authDB is typically "admin".
func AuthenticateBackend(conn net.Conn, user, password, authDB string) error {
	sc := NewSCRAMClient(user, password)

	// Step 1: saslStart with client-first-message.
	clientFirst := sc.ClientFirstMessage()
	startCmd, err := BuildSASLStartCommand("SCRAM-SHA-256", []byte(clientFirst), authDB)
	if err != nil {
		return fmt.Errorf("build saslStart: %w", err)
	}
	if err := WriteMessage(conn, startCmd); err != nil {
		return fmt.Errorf("send saslStart: %w", err)
	}

	// Read server's saslStart response (contains server-first-message).
	resp, err := ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("read saslStart response: %w", err)
	}
	_, respDoc, err := ParseOpMsgBody(resp.Body)
	if err != nil {
		return fmt.Errorf("parse saslStart response: %w", err)
	}
	payload, convID, _, err := ExtractSASLPayload(respDoc)
	if err != nil {
		return fmt.Errorf("extract saslStart payload: %w", err)
	}

	// Step 2: saslContinue with client-final-message.
	clientFinal, err := sc.ClientFinalMessage(string(payload))
	if err != nil {
		return fmt.Errorf("compute client-final: %w", err)
	}
	contCmd, err := BuildSASLContinueCommand([]byte(clientFinal), convID, authDB)
	if err != nil {
		return fmt.Errorf("build saslContinue: %w", err)
	}
	if err := WriteMessage(conn, contCmd); err != nil {
		return fmt.Errorf("send saslContinue: %w", err)
	}

	// Read server's saslContinue response (contains server-final-message).
	resp, err = ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("read saslContinue response: %w", err)
	}
	_, respDoc, err = ParseOpMsgBody(resp.Body)
	if err != nil {
		return fmt.Errorf("parse saslContinue response: %w", err)
	}
	payload, _, done, err := ExtractSASLPayload(respDoc)
	if err != nil {
		return fmt.Errorf("extract saslContinue payload: %w", err)
	}

	if err := sc.VerifyServerFinal(string(payload)); err != nil {
		return fmt.Errorf("verify server: %w", err)
	}

	// Some servers need an additional empty saslContinue to finalize.
	if !done {
		finalCmd, err := BuildSASLContinueCommand([]byte{}, convID, authDB)
		if err != nil {
			return fmt.Errorf("build final saslContinue: %w", err)
		}
		if err := WriteMessage(conn, finalCmd); err != nil {
			return fmt.Errorf("send final saslContinue: %w", err)
		}
		resp, err = ReadMessage(conn)
		if err != nil {
			return fmt.Errorf("read final saslContinue response: %w", err)
		}
		_, respDoc, err = ParseOpMsgBody(resp.Body)
		if err != nil {
			return fmt.Errorf("parse final response: %w", err)
		}
		_, _, _, err = ExtractSASLPayload(respDoc)
		if err != nil {
			return fmt.Errorf("final saslContinue: %w", err)
		}
	}

	return nil
}

// SCRAMServer holds state for faking SCRAM-SHA-256 to a client.
// The proxy accepts clients that authenticate with the well-known dummy
// password (DummyPassword) since Tailscale identity is the real credential.
type SCRAMServer struct {
	serverNonce    string
	salt           []byte
	iterations     int
	conversationID int32
}

// NewSCRAMServer creates a fake SCRAM-SHA-256 server with random parameters.
func NewSCRAMServer() *SCRAMServer {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic("generate salt: " + err.Error())
	}
	return &SCRAMServer{
		serverNonce:    generateSCRAMNonce(),
		salt:           salt,
		iterations:     4096,
		conversationID: 1,
	}
}

// --- SCRAM crypto primitives ---

type scramServerFirstParsed struct {
	nonce      string
	salt       []byte
	iterations int
}

func parseSCRAMServerFirst(msg string) (*scramServerFirstParsed, error) {
	var result scramServerFirstParsed
	for _, part := range strings.Split(msg, ",") {
		if strings.HasPrefix(part, "r=") {
			result.nonce = part[2:]
		} else if strings.HasPrefix(part, "s=") {
			salt, err := base64.StdEncoding.DecodeString(part[2:])
			if err != nil {
				return nil, fmt.Errorf("decode salt: %w", err)
			}
			result.salt = salt
		} else if strings.HasPrefix(part, "i=") {
			iter, err := strconv.Atoi(part[2:])
			if err != nil {
				return nil, fmt.Errorf("parse iterations: %w", err)
			}
			result.iterations = iter
		}
	}
	if result.nonce == "" || result.salt == nil || result.iterations == 0 {
		return nil, fmt.Errorf("incomplete server-first-message: %q", msg)
	}
	return &result, nil
}

// scramHi implements PBKDF2 with HMAC-SHA-256.
func scramHi(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)

	result := make([]byte, len(u))
	copy(result, u)

	for i := 1; i < iterations; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := range result {
			result[j] ^= u[j]
		}
	}
	return result
}

func scramHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func scramSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func scramXOR(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func generateSCRAMNonce() string {
	b := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("generate nonce: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

func saslPrep(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}
