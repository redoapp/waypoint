package pgwire

import (
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
