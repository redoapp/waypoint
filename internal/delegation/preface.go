package delegation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	ProtocolVersion          = byte(1)
	DefaultMaxCredentialSize = 8 * 1024
	DefaultPrefaceTimeout    = 5 * time.Second
)

var protocolMagic = [4]byte{'W', 'P', 'D', 'G'}

// ReadPreface consumes exactly one delegation preface without reading any
// following PostgreSQL bytes from the stream.
func ReadPreface(conn net.Conn, timeout time.Duration, maxCredentialSize int) (string, error) {
	if timeout <= 0 {
		timeout = DefaultPrefaceTimeout
	}
	if maxCredentialSize <= 0 {
		maxCredentialSize = DefaultMaxCredentialSize
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", fmt.Errorf("set preface deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	header := make([]byte, 9)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read delegation preface header: %w", err)
	}
	if string(header[:4]) != string(protocolMagic[:]) {
		return "", errors.New("invalid delegation protocol identifier")
	}
	if header[4] != ProtocolVersion {
		return "", fmt.Errorf("unsupported delegation protocol version %d", header[4])
	}
	credentialLength := binary.BigEndian.Uint32(header[5:])
	if credentialLength == 0 {
		return "", errors.New("delegation credential is missing")
	}
	if credentialLength > uint32(maxCredentialSize) {
		return "", fmt.Errorf("delegation credential length %d exceeds maximum %d", credentialLength, maxCredentialSize)
	}

	credential := make([]byte, credentialLength)
	if _, err := io.ReadFull(conn, credential); err != nil {
		return "", fmt.Errorf("read delegation credential: %w", err)
	}
	return string(credential), nil
}

// WritePreface writes one complete delegation preface. It is exported for
// clients and local interoperability tests.
func WritePreface(w io.Writer, credential string) error {
	if credential == "" {
		return errors.New("delegation credential is missing")
	}
	if len(credential) > DefaultMaxCredentialSize {
		return fmt.Errorf("delegation credential length %d exceeds maximum %d", len(credential), DefaultMaxCredentialSize)
	}

	frame := make([]byte, 9+len(credential))
	copy(frame[:4], protocolMagic[:])
	frame[4] = ProtocolVersion
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(credential)))
	copy(frame[9:], credential)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return fmt.Errorf("write delegation preface: %w", err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
