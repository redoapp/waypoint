package pgwire

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/redoapp/waypoint/internal/config"
)

var (
	ErrTLSRequired = errors.New("postgres client TLS required")
	// ErrCancelRequest indicates the client sent a Postgres CancelRequest
	// rather than a startup message. We do not forward query cancellation, so
	// the proxy treats this as a benign close rather than an error.
	ErrCancelRequest = errors.New("postgres cancel request")
)

// Special request codes carried in the first Int32 of a startup packet. Each is
// 1234 in the high 16 bits and 567x in the low 16 bits (see PostgreSQL protocol
// "Message Formats"). Normal startup packets instead carry a protocol version
// (e.g. 196608 for 3.0).
const (
	sslRequestCode    = 80877103 // SSLRequest    (1234<<16 | 5679)
	gssEncRequestCode = 80877104 // GSSENCRequest (1234<<16 | 5680)
	cancelRequestCode = 80877102 // CancelRequest (1234<<16 | 5678)
)

// ReadStartupMessage reads the initial PG startup message from the client and
// negotiates Postgres SSL/TLS when enabled. It returns the live client
// connection to use for the rest of the session, which may be TLS-wrapped.
func ReadStartupMessage(conn net.Conn, mode config.PostgresTLSMode, tlsConfig *tls.Config) (net.Conn, *pgproto3.StartupMessage, error) {
	tlsAccepted := false
	for {
		msgLen, body, err := readStartupPacket(conn)
		if err != nil {
			return conn, nil, err
		}

		if isSSLRequest(msgLen, body) {
			switch mode {
			case config.PostgresTLSOff:
				if _, err := conn.Write([]byte{'N'}); err != nil {
					return conn, nil, fmt.Errorf("deny SSL: %w", err)
				}
			case config.PostgresTLSOptional, config.PostgresTLSRequire:
				if tlsConfig == nil {
					return conn, nil, fmt.Errorf("TLS requested but no server TLS config is available")
				}
				if _, err := conn.Write([]byte{'S'}); err != nil {
					return conn, nil, fmt.Errorf("accept SSL: %w", err)
				}
				tlsConn := tls.Server(conn, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					return conn, nil, fmt.Errorf("TLS handshake: %w", err)
				}
				conn = tlsConn
				tlsAccepted = true
			default:
				return conn, nil, fmt.Errorf("unsupported TLS mode %q", mode)
			}
			continue
		}

		if isGSSEncRequest(msgLen, body) {
			// We don't support GSSAPI encryption. Decline with 'N'; a conforming
			// client falls back to a plain (or SSL) startup on the same connection.
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return conn, nil, fmt.Errorf("deny GSS encryption: %w", err)
			}
			continue
		}

		if isCancelRequest(msgLen, body) {
			// A CancelRequest is a complete frame, not a startup. Surface a
			// sentinel so the proxy closes cleanly without recording an error.
			return conn, nil, ErrCancelRequest
		}

		if mode == config.PostgresTLSRequire && !tlsAccepted {
			return conn, nil, ErrTLSRequired
		}

		var startup pgproto3.StartupMessage
		if err := startup.Decode(body); err != nil {
			return conn, nil, fmt.Errorf("decode startup: %w", err)
		}
		return conn, &startup, nil
	}
}

func readStartupPacket(conn net.Conn) (int, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, fmt.Errorf("read startup header: %w", err)
	}
	msgLen := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if msgLen < 4 || msgLen > 10240 {
		return 0, nil, fmt.Errorf("invalid startup message length: %d", msgLen)
	}

	body := make([]byte, msgLen-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, fmt.Errorf("read startup body: %w", err)
	}
	return msgLen, body, nil
}

func isSSLRequest(msgLen int, body []byte) bool {
	if msgLen != 8 || len(body) != 4 {
		return false
	}
	version := int(body[0])<<24 | int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	return version == sslRequestCode
}

func isGSSEncRequest(msgLen int, body []byte) bool {
	if msgLen != 8 || len(body) != 4 {
		return false
	}
	version := int(body[0])<<24 | int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	return version == gssEncRequestCode
}

// isCancelRequest reports whether the packet is a CancelRequest. Its layout is
// Int32(16) length, Int32 cancel code, Int32 backend PID, Int32 secret key — so
// the body (length-prefix excluded) is 12 bytes beginning with the cancel code.
func isCancelRequest(msgLen int, body []byte) bool {
	if msgLen != 16 || len(body) != 12 {
		return false
	}
	version := int(body[0])<<24 | int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	return version == cancelRequestCode
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
