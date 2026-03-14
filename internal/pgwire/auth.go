package pgwire

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// SendAuthOK sends AuthenticationOk to the client.
func SendAuthOK(conn net.Conn) error {
	msg := &pgproto3.AuthenticationOk{}
	buf, err := msg.Encode(nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf)
	return err
}

// HandleUpstreamAuth handles the authentication exchange with the upstream
// PostgreSQL server. Supports CleartextPassword, MD5Password, and
// SASL (SCRAM-SHA-256). Returns the pgproto3 Frontend so that callers
// (e.g. ForwardPostAuth) can continue reading from the same buffered reader.
func HandleUpstreamAuth(conn net.Conn, user, password string) (*pgproto3.Frontend, error) {
	backend := pgproto3.NewFrontend(conn, conn)

	for {
		msg, err := backend.Receive()
		if err != nil {
			return nil, fmt.Errorf("receive auth message: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			return backend, nil

		case *pgproto3.AuthenticationCleartextPassword:
			resp := &pgproto3.PasswordMessage{Password: password}
			if err := writeMsg(conn, resp); err != nil {
				return nil, fmt.Errorf("send cleartext password: %w", err)
			}

		case *pgproto3.AuthenticationMD5Password:
			hash := md5Hash(password, user, m.Salt)
			resp := &pgproto3.PasswordMessage{Password: hash}
			if err := writeMsg(conn, resp); err != nil {
				return nil, fmt.Errorf("send md5 password: %w", err)
			}

		case *pgproto3.AuthenticationSASL:
			if err := handleSCRAM(conn, backend, user, password, m); err != nil {
				return nil, fmt.Errorf("SCRAM auth: %w", err)
			}
			return backend, nil

		case *pgproto3.ErrorResponse:
			return nil, fmt.Errorf("upstream auth error: %s (code %s)", m.Message, m.Code)

		default:
			return nil, fmt.Errorf("unexpected auth message type: %T", msg)
		}
	}
}

type encodable interface {
	Encode([]byte) ([]byte, error)
}

func writeMsg(conn net.Conn, msg encodable) error {
	buf, err := msg.Encode(nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf)
	return err
}

// ForwardPostAuth forwards ParameterStatus, BackendKeyData, and
// ReadyForQuery messages from upstream to the client. Returns when
// ReadyForQuery is received. The fe parameter should be the Frontend
// returned by HandleUpstreamAuth to share the same buffered reader.
func ForwardPostAuth(fe *pgproto3.Frontend, client net.Conn) error {
	for {
		msg, err := fe.Receive()
		if err != nil {
			return fmt.Errorf("receive post-auth: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.ParameterStatus:
			if err := writeMsg(client, m); err != nil {
				return err
			}
		case *pgproto3.BackendKeyData:
			if err := writeMsg(client, m); err != nil {
				return err
			}
		case *pgproto3.ReadyForQuery:
			return writeMsg(client, m)
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("upstream error: %s (code %s)", m.Message, m.Code)
		default:
			if enc, ok := msg.(encodable); ok {
				if err := writeMsg(client, enc); err != nil {
					return err
				}
			}
		}
	}
}

// SendErrorResponse sends a PG ErrorResponse to the client.
func SendErrorResponse(conn net.Conn, severity, code, message string) {
	msg := &pgproto3.ErrorResponse{
		Severity: severity,
		Code:     code,
		Message:  message,
	}
	writeMsg(conn, msg)
}

func md5Hash(password, user string, salt [4]byte) string {
	inner := md5.Sum([]byte(password + user))
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt[:]...))
	return "md5" + hex.EncodeToString(outer[:])
}

func handleSCRAM(conn net.Conn, fe *pgproto3.Frontend, user, password string, saslMsg *pgproto3.AuthenticationSASL) error {
	found := false
	for _, mech := range saslMsg.AuthMechanisms {
		if mech == "SCRAM-SHA-256" {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("server does not support SCRAM-SHA-256, offered: %v", saslMsg.AuthMechanisms)
	}

	sc := newSCRAMClient(user, password)

	clientFirst := sc.clientFirstMessage()
	initial := &pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256",
		Data:          []byte(clientFirst),
	}
	if err := writeMsg(conn, initial); err != nil {
		return err
	}

	msg, err := fe.Receive()
	if err != nil {
		return err
	}
	saslContinue, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return fmt.Errorf("expected SASLContinue, got %T", msg)
	}

	clientFinal, err := sc.clientFinalMessage(string(saslContinue.Data))
	if err != nil {
		return err
	}

	resp := &pgproto3.SASLResponse{Data: []byte(clientFinal)}
	if err := writeMsg(conn, resp); err != nil {
		return err
	}

	msg, err = fe.Receive()
	if err != nil {
		return err
	}
	saslFinal, ok := msg.(*pgproto3.AuthenticationSASLFinal)
	if !ok {
		if _, ok := msg.(*pgproto3.AuthenticationOk); ok {
			return nil
		}
		return fmt.Errorf("expected SASLFinal, got %T", msg)
	}

	if err := sc.verifyServerFinal(string(saslFinal.Data)); err != nil {
		return err
	}

	msg, err = fe.Receive()
	if err != nil {
		return err
	}
	if _, ok := msg.(*pgproto3.AuthenticationOk); !ok {
		return fmt.Errorf("expected AuthenticationOk after SCRAM, got %T", msg)
	}

	return nil
}

// scramClient is a minimal SCRAM-SHA-256 client implementation.
type scramClient struct {
	user, password string
	nonce          string
	clientFirst    string
	serverFirst    string
	saltedPassword []byte
	authMessage    string
}

func newSCRAMClient(user, password string) *scramClient {
	return &scramClient{user: user, password: password}
}

func (s *scramClient) clientFirstMessage() string {
	s.nonce = generateNonce()
	s.clientFirst = fmt.Sprintf("n,,n=%s,r=%s", saslPrepUsername(s.user), s.nonce)
	return s.clientFirst
}

func (s *scramClient) clientFinalMessage(serverFirst string) (string, error) {
	s.serverFirst = serverFirst

	parsed, err := parseServerFirst(serverFirst)
	if err != nil {
		return "", err
	}

	if len(parsed.nonce) <= len(s.nonce) || parsed.nonce[:len(s.nonce)] != s.nonce {
		return "", fmt.Errorf("server nonce does not start with client nonce")
	}

	s.saltedPassword = hi([]byte(saslPrepPassword(s.password)), parsed.salt, parsed.iterations)

	clientKey := hmacSHA256(s.saltedPassword, []byte("Client Key"))
	storedKey := sha256Hash(clientKey)

	clientFirstBare := s.clientFirst[3:]
	channelBinding := "c=biws"
	clientFinalWithoutProof := fmt.Sprintf("%s,r=%s", channelBinding, parsed.nonce)
	s.authMessage = fmt.Sprintf("%s,%s,%s", clientFirstBare, serverFirst, clientFinalWithoutProof)

	clientSignature := hmacSHA256(storedKey, []byte(s.authMessage))
	clientProof := xorBytes(clientKey, clientSignature)

	return fmt.Sprintf("%s,p=%s", clientFinalWithoutProof, base64Encode(clientProof)), nil
}

func (s *scramClient) verifyServerFinal(serverFinal string) error {
	parsed, err := parseServerFinal(serverFinal)
	if err != nil {
		return err
	}

	serverKey := hmacSHA256(s.saltedPassword, []byte("Server Key"))
	expected := hmacSHA256(serverKey, []byte(s.authMessage))

	if !hmacEqual(parsed.verifier, expected) {
		return fmt.Errorf("server signature mismatch")
	}
	return nil
}

func generateNonce() string {
	b := make([]byte, 24)
	if _, err := io.ReadFull(cryptoRandReader, b); err != nil {
		panic("failed to generate nonce: " + err.Error())
	}
	return base64Encode(b)
}
