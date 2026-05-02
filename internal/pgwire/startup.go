package pgwire

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// ReadStartupMessage reads the initial PG startup message from the client.
// Handles SSL negotiation (denies SSL, client retries with plaintext).
func ReadStartupMessage(conn net.Conn) (*pgproto3.StartupMessage, error) {
	for {
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, fmt.Errorf("read startup header: %w", err)
		}
		msgLen := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])

		if msgLen < 4 || msgLen > 10240 {
			return nil, fmt.Errorf("invalid startup message length: %d", msgLen)
		}

		body := make([]byte, msgLen-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, fmt.Errorf("read startup body: %w", err)
		}

		// Check for SSLRequest (version 80877103 = 0x04D2162F).
		if msgLen == 8 {
			version := int(body[0])<<24 | int(body[1])<<16 | int(body[2])<<8 | int(body[3])
			if version == 80877103 {
				// Deny SSL with 'N'.
				if _, err := conn.Write([]byte{'N'}); err != nil {
					return nil, fmt.Errorf("deny SSL: %w", err)
				}
				continue
			}
		}

		// Decode expects the message body without the 4-byte length prefix.
		var startup pgproto3.StartupMessage
		if err := startup.Decode(body); err != nil {
			return nil, fmt.Errorf("decode startup: %w", err)
		}

		return &startup, nil
	}
}

// UpgradeToTLS sends an SSLRequest to the backend and upgrades the connection
// to TLS. Returns the TLS-wrapped connection on success.
func UpgradeToTLS(conn net.Conn) (net.Conn, error) {
	// SSLRequest: length=8, version=80877103 (0x04D2162F)
	sslReq := []byte{0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F}
	if _, err := conn.Write(sslReq); err != nil {
		return nil, fmt.Errorf("send SSLRequest: %w", err)
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read SSL response: %w", err)
	}

	if resp[0] != 'S' {
		return nil, fmt.Errorf("backend rejected SSL (response: %c)", resp[0])
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	return tlsConn, nil
}

// WriteStartupMessage sends a startup message to the upstream backend.
func WriteStartupMessage(conn net.Conn, user, database string, params map[string]string) error {
	msg := &pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      make(map[string]string),
	}
	msg.Parameters["user"] = user
	msg.Parameters["database"] = database
	for k, v := range params {
		if k != "user" && k != "database" {
			msg.Parameters[k] = v
		}
	}

	encoded, err := msg.Encode(nil)
	if err != nil {
		return err
	}
	_, err = conn.Write(encoded)
	return err
}
