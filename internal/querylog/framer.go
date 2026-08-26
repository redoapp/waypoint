package querylog

import (
	"io"
	"net"
	"time"
)

// maxBufferedMessage bounds how large a single protocol message may be before
// the framer stops buffering it. Anything bigger — a COPY payload, a bulk
// insert — is streamed straight through in chunks and only noted, never held
// in memory or decoded.
const maxBufferedMessage = 1 << 20 // 1 MiB

// framedConn is the shared machinery behind the Postgres and MongoDB taps: a
// net.Conn wrapper that reassembles whole protocol messages on Read, hands
// each one to an observer, and then serves the identical bytes onward.
//
// Byte transparency is the invariant that matters. These wrappers sit inside
// restrict.Relay, whose byte counting enforces the per-user bandwidth limits,
// so a wrapper that swallowed or duplicated a byte would corrupt both the
// protocol and the limit accounting. Every byte read from the underlying
// connection is returned to the caller exactly once, in order.
//
// The approach mirrors mongowire.TopologyRewriter, which already establishes
// this pattern as safe around the relay.
type framedConn struct {
	conn net.Conn

	// readHeader reads the next message header from r and reports the total
	// message size and how many header bytes it consumed. It returns the
	// header bytes so they can be replayed to the caller.
	readHeader func(r io.Reader) (hdr []byte, total int, err error)

	// observe is handed each complete message. It must not retain the slice.
	observe func(msg []byte)

	// observeOversized is called for a message too large to buffer.
	observeOversized func(hdr []byte, total int)

	buf       []byte // complete-but-undelivered bytes
	remaining int    // bytes of an oversized message still to stream through
}

func (f *framedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Serve anything already framed but not yet handed over.
	if len(f.buf) > 0 {
		n := copy(p, f.buf)
		f.buf = f.buf[n:]
		return n, nil
	}

	// Stream the tail of an oversized message without buffering it.
	if f.remaining > 0 {
		limit := p
		if len(limit) > f.remaining {
			limit = limit[:f.remaining]
		}
		n, err := f.conn.Read(limit)
		f.remaining -= n
		return n, err
	}

	hdr, total, err := f.readHeader(f.conn)
	if err != nil {
		// A partial header still has to reach the caller, or the relay would
		// silently truncate the stream.
		if len(hdr) > 0 {
			return f.serve(p, hdr)
		}
		return 0, err
	}

	// A header we cannot make sense of: pass it through untouched and let
	// the peer decide what to do. Better a pass-through than a dropped byte.
	if total <= len(hdr) {
		return f.serve(p, hdr)
	}

	if total > maxBufferedMessage {
		if f.observeOversized != nil {
			f.observeOversized(hdr, total)
		}
		f.remaining = total - len(hdr)
		return f.serve(p, hdr)
	}

	msg := make([]byte, total)
	copy(msg, hdr)
	if n, err := io.ReadFull(f.conn, msg[len(hdr):]); err != nil {
		// The connection died mid-message. Deliver the header *and* whatever
		// body bytes arrived — ReadFull reports how many it managed — since
		// dropping them would truncate the peer's stream and undercount the
		// bytes the relay actually moved. The error surfaces on the next Read.
		return f.serve(p, msg[:len(hdr)+n])
	}

	if f.observe != nil {
		f.observe(msg)
	}
	return f.serve(p, msg)
}

// serve hands msg to the caller, buffering whatever does not fit.
func (f *framedConn) serve(p []byte, msg []byte) (int, error) {
	n := copy(p, msg)
	if n < len(msg) {
		f.buf = append(f.buf[:0:0], msg[n:]...)
	}
	return n, nil
}

func (f *framedConn) Write(p []byte) (int, error) { return f.conn.Write(p) }
func (f *framedConn) Close() error                { return f.conn.Close() }
func (f *framedConn) LocalAddr() net.Addr         { return f.conn.LocalAddr() }
func (f *framedConn) RemoteAddr() net.Addr        { return f.conn.RemoteAddr() }
func (f *framedConn) SetDeadline(t time.Time) error {
	return f.conn.SetDeadline(t)
}
func (f *framedConn) SetReadDeadline(t time.Time) error  { return f.conn.SetReadDeadline(t) }
func (f *framedConn) SetWriteDeadline(t time.Time) error { return f.conn.SetWriteDeadline(t) }
