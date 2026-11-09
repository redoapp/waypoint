package pgwire

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/redoapp/waypoint/internal/config"
)

var (
	ErrTLSRequired = errors.New("postgres client TLS required")
	// ErrCancelRequest indicates the client sent a Postgres CancelRequest
	// rather than a startup message. We do not forward query cancellation, so
	// the proxy treats this as a benign close rather than an error.
	ErrCancelRequest = errors.New("postgres cancel request")
	// ErrUnsupportedProtocol indicates the client asked for a protocol major
	// version other than 3. Callers should answer with SQLSTATE 0A000.
	ErrUnsupportedProtocol = errors.New("unsupported frontend protocol")
)

// Protocol version negotiation. Waypoint speaks protocol 3.0 to clients and to
// backends. PostgreSQL 18 introduced protocol 3.2 (longer cancel keys) and
// clients may also send "_pq_."-prefixed protocol options. Like a real
// PostgreSQL server, Waypoint accepts any 3.x startup and answers a newer minor
// version or unknown protocol options with NegotiateProtocolVersion, after which
// a conforming client continues on 3.0.
const (
	supportedProtocolMajor = 3
	supportedProtocolMinor = 0
	protocolOptionPrefix   = "_pq_."

	// maxCancelKeyLength is the largest secret key a protocol 3.2 server may
	// hand out in BackendKeyData, and so the largest key a CancelRequest may
	// carry.
	maxCancelKeyLength = 256
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

		startup, unsupportedOptions, negotiate, err := decodeStartup(body)
		if err != nil {
			return conn, nil, err
		}
		if negotiate {
			if err := writeNegotiateProtocolVersion(conn, pgproto3.ProtocolVersionNumber, unsupportedOptions); err != nil {
				return conn, nil, fmt.Errorf("negotiate protocol version: %w", err)
			}
		}
		return conn, startup, nil
	}
}

// decodeStartup decodes a StartupMessage body for any protocol 3.x version.
// It strips "_pq_." protocol options from the returned parameters (Waypoint
// supports none of them, and they must never reach the backend startup) and
// reports whether the client needs a NegotiateProtocolVersion reply: true when
// the client requested a minor version newer than 3.0 or sent any protocol
// options. The returned message always carries ProtocolVersion 3.0, the version
// the session actually runs at.
func decodeStartup(body []byte) (*pgproto3.StartupMessage, []string, bool, error) {
	if len(body) < 4 {
		return nil, nil, false, errors.New("decode startup: startup message too short")
	}
	requested := binary.BigEndian.Uint32(body)
	major, minor := requested>>16, requested&0xffff
	if major != supportedProtocolMajor {
		return nil, nil, false, fmt.Errorf("%w %d.%d: server supports %d.0 to %d.%d",
			ErrUnsupportedProtocol, major, minor,
			supportedProtocolMajor, supportedProtocolMajor, supportedProtocolMinor)
	}

	// pgproto3 only decodes 3.0 startups, but the parameter layout is identical
	// for every 3.x minor version, so decode a copy stamped as 3.0.
	normalized := make([]byte, len(body))
	copy(normalized, body)
	binary.BigEndian.PutUint32(normalized, pgproto3.ProtocolVersionNumber)

	var startup pgproto3.StartupMessage
	if err := startup.Decode(normalized); err != nil {
		return nil, nil, false, fmt.Errorf("decode startup: %w", err)
	}

	var unsupported []string
	for k := range startup.Parameters {
		if strings.HasPrefix(k, protocolOptionPrefix) {
			unsupported = append(unsupported, k)
			delete(startup.Parameters, k)
		}
	}
	sort.Strings(unsupported)

	negotiate := minor > supportedProtocolMinor || len(unsupported) > 0
	return &startup, unsupported, negotiate, nil
}

// writeNegotiateProtocolVersion sends a NegotiateProtocolVersion ('v') message:
// Int32 protocol version the server will use, Int32 count of unrecognized
// protocol options, then each option name as a C string. The protocol docs
// describe the first field as the newest supported minor version, but
// PostgreSQL servers send the full version number (major<<16 | minor) and libpq
// rejects anything below 3.0 as a downgrade, so the full number is sent here.
func writeNegotiateProtocolVersion(conn net.Conn, version uint32, options []string) error {
	size := 4 + 4 + 4
	for _, o := range options {
		size += len(o) + 1
	}
	buf := make([]byte, 0, 1+size)
	buf = append(buf, 'v')
	buf = binary.BigEndian.AppendUint32(buf, uint32(size))
	buf = binary.BigEndian.AppendUint32(buf, version)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(options)))
	for _, o := range options {
		buf = append(buf, o...)
		buf = append(buf, 0)
	}
	_, err := conn.Write(buf)
	return err
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
// Int32 length, Int32 cancel code, Int32 backend PID, then the secret key. The
// key is 4 bytes in protocol 3.0 and up to 256 bytes in protocol 3.2, so the
// body (length-prefix excluded) is 12 to 264 bytes beginning with the cancel
// code.
func isCancelRequest(msgLen int, body []byte) bool {
	if msgLen < 16 || msgLen > 12+maxCancelKeyLength || len(body) != msgLen-4 {
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
