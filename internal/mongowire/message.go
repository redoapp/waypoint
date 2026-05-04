package mongowire

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// MongoDB wire protocol opcodes.
const (
	OpQuery int32 = 2004 // legacy OP_QUERY (used for initial isMaster handshake)
	OpReply int32 = 1    // legacy OP_REPLY
	OpMsg   int32 = 2013
)

// OP_MSG flag bits.
const (
	FlagChecksumPresent uint32 = 1 << 0
	FlagMoreToCome      uint32 = 1 << 1
	FlagExhaustAllowed  uint32 = 1 << 16
)

// OP_MSG section kinds.
const (
	SectionBody             byte = 0
	SectionDocumentSequence byte = 1
)

// Header is a MongoDB wire protocol message header (16 bytes).
type Header struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

// Message is a complete MongoDB wire protocol message (header + body).
type Message struct {
	Header Header
	Body   []byte // everything after the 16-byte header
}

const headerSize = 16

// HeaderSize is the size of a MongoDB wire protocol message header (16 bytes).
const HeaderSize = headerSize

const maxMessageSize = 48 * 1024 * 1024 // 48 MB

var nextRequestID int32

// NextRequestID returns a monotonically increasing request ID.
func NextRequestID() int32 {
	return atomic.AddInt32(&nextRequestID, 1)
}

// ReadMessage reads a complete wire protocol message from conn.
func ReadMessage(conn net.Conn) (*Message, error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	length := int32(binary.LittleEndian.Uint32(hdr[0:4]))
	if length < headerSize || length > int32(maxMessageSize) {
		return nil, fmt.Errorf("invalid message length: %d", length)
	}

	body := make([]byte, length-headerSize)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return &Message{
		Header: Header{
			MessageLength: length,
			RequestID:     int32(binary.LittleEndian.Uint32(hdr[4:8])),
			ResponseTo:    int32(binary.LittleEndian.Uint32(hdr[8:12])),
			OpCode:        int32(binary.LittleEndian.Uint32(hdr[12:16])),
		},
		Body: body,
	}, nil
}

// WriteMessage writes a complete wire protocol message to conn.
func WriteMessage(conn net.Conn, msg *Message) error {
	totalLen := headerSize + len(msg.Body)
	buf := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(msg.Header.RequestID))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(msg.Header.ResponseTo))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(msg.Header.OpCode))
	copy(buf[headerSize:], msg.Body)
	_, err := conn.Write(buf)
	return err
}

// ParseOpMsgBody extracts the flags and body BSON document from an OP_MSG body.
// Only parses the first kind-0 section (single document body).
// Handles FlagChecksumPresent by excluding the trailing 4-byte CRC32 from
// section parsing.
func ParseOpMsgBody(body []byte) (flags uint32, doc bson.Raw, err error) {
	if len(body) < 5 { // 4 bytes flags + at least 1 byte section
		return 0, nil, fmt.Errorf("OP_MSG body too short: %d bytes", len(body))
	}

	flags = binary.LittleEndian.Uint32(body[0:4])
	rem := body[4:]

	// If the checksum flag is set, exclude the trailing 4-byte CRC32.
	if flags&FlagChecksumPresent != 0 {
		if len(rem) < 4 {
			return 0, nil, fmt.Errorf("OP_MSG too short for checksum")
		}
		rem = rem[:len(rem)-4]
	}

	// Read sections until we find a kind-0 (body document).
	for len(rem) > 0 {
		kind := rem[0]
		rem = rem[1:]

		switch kind {
		case SectionBody:
			if len(rem) < 4 {
				return 0, nil, fmt.Errorf("section body too short")
			}
			docLen := int(binary.LittleEndian.Uint32(rem[0:4]))
			if docLen < 5 || docLen > len(rem) {
				return 0, nil, fmt.Errorf("invalid BSON document length: %d", docLen)
			}
			return flags, bson.Raw(rem[:docLen]), nil

		case SectionDocumentSequence:
			// Skip document sequence sections.
			if len(rem) < 4 {
				return 0, nil, fmt.Errorf("document sequence section too short")
			}
			seqLen := int(binary.LittleEndian.Uint32(rem[0:4]))
			if seqLen < 4 || seqLen > len(rem) {
				return 0, nil, fmt.Errorf("invalid document sequence length: %d", seqLen)
			}
			rem = rem[seqLen:]

		default:
			return 0, nil, fmt.Errorf("unknown OP_MSG section kind: %d", kind)
		}
	}

	return 0, nil, fmt.Errorf("no body section found in OP_MSG")
}

// BuildOpMsg constructs an OP_MSG wire body from a BSON document.
func BuildOpMsg(flags uint32, doc bson.Raw) []byte {
	// flags (4) + section kind (1) + document
	body := make([]byte, 4+1+len(doc))
	binary.LittleEndian.PutUint32(body[0:4], flags)
	body[4] = SectionBody
	copy(body[5:], doc)
	return body
}

// NewOpMsgMessage creates a complete Message from a BSON document.
func NewOpMsgMessage(responseTo int32, doc bson.Raw) *Message {
	body := BuildOpMsg(0, doc)
	return &Message{
		Header: Header{
			RequestID:  NextRequestID(),
			ResponseTo: responseTo,
			OpCode:     OpMsg,
		},
		Body: body,
	}
}

// ParseOpQueryBody extracts the query document from a legacy OP_QUERY body.
// OP_QUERY body layout: flags(4) + fullCollectionName(cstring) + numberToSkip(4) + numberToReturn(4) + query(BSON)
func ParseOpQueryBody(body []byte) (doc bson.Raw, err error) {
	if len(body) < 12 {
		return nil, fmt.Errorf("OP_QUERY body too short: %d bytes", len(body))
	}
	rem := body[4:] // skip flags

	// Skip the full collection name (null-terminated string).
	idx := 0
	for idx < len(rem) && rem[idx] != 0 {
		idx++
	}
	if idx >= len(rem) {
		return nil, fmt.Errorf("unterminated collection name in OP_QUERY")
	}
	rem = rem[idx+1:] // skip past null terminator

	if len(rem) < 8 {
		return nil, fmt.Errorf("OP_QUERY too short after collection name")
	}
	rem = rem[8:] // skip numberToSkip + numberToReturn

	if len(rem) < 4 {
		return nil, fmt.Errorf("no query document in OP_QUERY")
	}
	docLen := int(binary.LittleEndian.Uint32(rem[0:4]))
	if docLen < 5 || docLen > len(rem) {
		return nil, fmt.Errorf("invalid query document length: %d", docLen)
	}
	return bson.Raw(rem[:docLen]), nil
}

// BuildOpReply constructs a legacy OP_REPLY message body from a BSON document.
func BuildOpReply(doc bson.Raw) []byte {
	// OP_REPLY body: responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + document
	body := make([]byte, 20+len(doc))
	// responseFlags = 0, cursorID = 0, startingFrom = 0, numberReturned = 1
	binary.LittleEndian.PutUint32(body[16:20], 1) // numberReturned
	copy(body[20:], doc)
	return body
}

// NewOpReplyMessage creates a complete OP_REPLY Message from a BSON document.
func NewOpReplyMessage(responseTo int32, doc bson.Raw) *Message {
	body := BuildOpReply(doc)
	return &Message{
		Header: Header{
			RequestID:  NextRequestID(),
			ResponseTo: responseTo,
			OpCode:     OpReply,
		},
		Body: body,
	}
}

// ForwardMessage reads a raw message from src and writes it to dst unchanged.
// Returns the raw bytes for inspection if needed.
func ForwardMessage(dst, src net.Conn) (*Message, error) {
	msg, err := ReadMessage(src)
	if err != nil {
		return nil, err
	}
	if err := WriteMessage(dst, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
