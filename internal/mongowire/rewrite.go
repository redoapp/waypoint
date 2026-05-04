package mongowire

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// TopologyRewriter wraps a net.Conn (the backend connection) and rewrites
// MongoDB topology responses so replica set member addresses point to the
// proxy instead of the backend's internal addresses.
//
// It implements net.Conn. Reads from this connection return bytes with
// topology fields rewritten. Writes pass through unchanged.
//
// This is inserted between restrict.Relay and the real backend connection
// so that the raw relay's byte counting still works correctly.
type TopologyRewriter struct {
	conn      net.Conn
	proxyAddr string

	mu     sync.Mutex
	buf    []byte // buffered rewritten bytes not yet consumed by Read
	rawBuf []byte // reusable read buffer
}

// NewTopologyRewriter creates a wrapper that rewrites topology responses
// read from conn, replacing member addresses with proxyAddr.
func NewTopologyRewriter(conn net.Conn, proxyAddr string) *TopologyRewriter {
	return &TopologyRewriter{
		conn:      conn,
		proxyAddr: proxyAddr,
		rawBuf:    make([]byte, 64*1024),
	}
}

// Read reads from the underlying connection. If a complete OP_MSG is
// available and contains topology info, it's rewritten before returning.
//
// For simplicity and reliability, this uses a message-boundary-aware approach:
// read a complete wire message, optionally rewrite it, then serve it to the caller.
func (r *TopologyRewriter) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Serve buffered bytes first.
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}

	// Read the 4-byte message length header.
	var hdr [4]byte
	if _, err := io.ReadFull(r.conn, hdr[:]); err != nil {
		return 0, err
	}
	msgLen := int(binary.LittleEndian.Uint32(hdr[:]))
	if msgLen < headerSize || msgLen > maxMessageSize {
		// Not a valid message or too large — pass through the header bytes
		// and let the caller handle whatever comes next.
		n := copy(p, hdr[:])
		return n, nil
	}

	// Read the rest of the message.
	msg := make([]byte, msgLen)
	copy(msg, hdr[:])
	if _, err := io.ReadFull(r.conn, msg[4:]); err != nil {
		return 0, err
	}

	// Check if this is an OP_MSG that might contain topology info.
	if msgLen >= headerSize {
		opCode := int32(binary.LittleEndian.Uint32(msg[12:16]))
		if opCode == OpMsg {
			body := msg[headerSize:]
			rewritten := RewriteTopology(body, r.proxyAddr)
			if len(rewritten) != len(body) {
				// Body size changed — rebuild the complete message.
				newMsg := make([]byte, headerSize+len(rewritten))
				binary.LittleEndian.PutUint32(newMsg[0:4], uint32(len(newMsg)))
				copy(newMsg[4:headerSize], msg[4:headerSize]) // requestID, responseTo, opCode
				copy(newMsg[headerSize:], rewritten)
				msg = newMsg
			}
		}
	}

	// Serve the message bytes to the caller, buffering any excess.
	n := copy(p, msg)
	if n < len(msg) {
		r.buf = append(r.buf[:0], msg[n:]...)
	}
	return n, nil
}

// Write passes through to the underlying connection unchanged.
func (r *TopologyRewriter) Write(p []byte) (int, error) {
	return r.conn.Write(p)
}

// Close closes the underlying connection.
func (r *TopologyRewriter) Close() error {
	return r.conn.Close()
}

// LocalAddr returns the underlying connection's local address.
func (r *TopologyRewriter) LocalAddr() net.Addr {
	return r.conn.LocalAddr()
}

// RemoteAddr returns the underlying connection's remote address.
func (r *TopologyRewriter) RemoteAddr() net.Addr {
	return r.conn.RemoteAddr()
}

// SetDeadline sets the underlying connection's deadline.
func (r *TopologyRewriter) SetDeadline(t time.Time) error {
	return r.conn.SetDeadline(t)
}

// SetReadDeadline sets the underlying connection's read deadline.
func (r *TopologyRewriter) SetReadDeadline(t time.Time) error {
	return r.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the underlying connection's write deadline.
func (r *TopologyRewriter) SetWriteDeadline(t time.Time) error {
	return r.conn.SetWriteDeadline(t)
}
