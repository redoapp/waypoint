package mongowire

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// buildWireMessage constructs a complete wire protocol message (header + body).
func buildWireMessage(opCode int32, body []byte) []byte {
	totalLen := headerSize + len(body)
	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(msg[4:8], 1)  // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0) // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], uint32(opCode))
	copy(msg[headerSize:], body)
	return msg
}

func TestTopologyRewriter_RewritesTopology(t *testing.T) {
	// Build a wire message with topology info.
	raw, _ := bson.Marshal(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"backend:27017"}},
		{Key: "me", Value: "backend:27017"},
		{Key: "primary", Value: "backend:27017"},
		{Key: "setName", Value: "rs0"},
		{Key: "ok", Value: 1.0},
	})
	body := BuildOpMsg(0, raw)
	wireMsg := buildWireMessage(OpMsg, body)

	// Pipe: write the message on one side, read through rewriter on the other.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		serverConn.Write(wireMsg)
		serverConn.Close()
	}()

	rw := NewTopologyRewriter(clientConn, "proxy:5555")

	// Read through the rewriter.
	result := make([]byte, len(wireMsg)+256) // extra space for potentially larger rewrite
	totalRead := 0
	for {
		n, err := rw.Read(result[totalRead:])
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	result = result[:totalRead]

	// Parse the rewritten message.
	if totalRead < headerSize {
		t.Fatalf("too short: %d bytes", totalRead)
	}
	msgLen := int(binary.LittleEndian.Uint32(result[0:4]))
	if msgLen != totalRead {
		t.Fatalf("message length %d != total read %d", msgLen, totalRead)
	}

	opCode := int32(binary.LittleEndian.Uint32(result[12:16]))
	if opCode != OpMsg {
		t.Fatalf("opcode = %d, want %d", opCode, OpMsg)
	}

	_, doc, err := ParseOpMsgBody(result[headerSize:])
	if err != nil {
		t.Fatalf("ParseOpMsgBody: %v", err)
	}

	var d bson.D
	if err := bson.Unmarshal(doc, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, e := range d {
		switch e.Key {
		case "hosts":
			arr := e.Value.(bson.A)
			if len(arr) != 1 || arr[0] != "proxy:5555" {
				t.Errorf("hosts not rewritten: %v", arr)
			}
		case "me":
			if e.Value != "proxy:5555" {
				t.Errorf("me not rewritten: %v", e.Value)
			}
		case "primary":
			if e.Value != "proxy:5555" {
				t.Errorf("primary not rewritten: %v", e.Value)
			}
		case "setName":
			if e.Value != "rs0" {
				t.Errorf("setName changed: %v", e.Value)
			}
		}
	}
}

func TestTopologyRewriter_RewritesTopologyWithMap(t *testing.T) {
	raw, _ := bson.Marshal(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"mongo1:27017", "mongo2:27017"}},
		{Key: "me", Value: "mongo2:27017"},
		{Key: "primary", Value: "mongo1:27017"},
		{Key: "ok", Value: 1.0},
	})
	body := BuildOpMsg(0, raw)
	wireMsg := buildWireMessage(OpMsg, body)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		serverConn.Write(wireMsg)
		serverConn.Close()
	}()

	rw := NewTopologyRewriterWithMap(clientConn, "proxy-fallback:27017", map[string]string{
		"mongo1:27017": "proxy:27017",
		"mongo2:27017": "proxy:27018",
	})

	result, err := readFullMessage(rw)
	if err != nil {
		t.Fatalf("read message: %v", err)
	}

	_, doc, err := ParseOpMsgBody(result[headerSize:])
	if err != nil {
		t.Fatalf("ParseOpMsgBody: %v", err)
	}
	var d bson.D
	if err := bson.Unmarshal(doc, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, e := range d {
		switch e.Key {
		case "hosts":
			arr := e.Value.(bson.A)
			if arr[0] != "proxy:27017" || arr[1] != "proxy:27018" {
				t.Errorf("hosts not mapped: %v", arr)
			}
		case "me":
			if e.Value != "proxy:27018" {
				t.Errorf("me = %q, want proxy:27018", e.Value)
			}
		case "primary":
			if e.Value != "proxy:27017" {
				t.Errorf("primary = %q, want proxy:27017", e.Value)
			}
		}
	}
}

func TestTopologyRewriter_RewritesSameLengthAddress(t *testing.T) {
	raw, _ := bson.Marshal(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"mongo1:27017"}},
		{Key: "ok", Value: 1.0},
	})
	wireMsg := buildWireMessage(OpMsg, BuildOpMsg(0, raw))

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		serverConn.Write(wireMsg)
		serverConn.Close()
	}()

	rw := NewTopologyRewriterWithMap(clientConn, "proxy1:27017", map[string]string{
		"mongo1:27017": "proxy1:27017",
	})
	result, err := readFullMessage(rw)
	if err != nil {
		t.Fatalf("read message: %v", err)
	}

	_, doc, err := ParseOpMsgBody(result[headerSize:])
	if err != nil {
		t.Fatalf("ParseOpMsgBody: %v", err)
	}
	var d bson.D
	if err := bson.Unmarshal(doc, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, e := range d {
		if e.Key == "hosts" {
			arr := e.Value.(bson.A)
			if arr[0] != "proxy1:27017" {
				t.Fatalf("hosts[0] = %q, want proxy1:27017", arr[0])
			}
		}
	}
}

func TestTopologyRewriter_PassthroughNonTopology(t *testing.T) {
	// Build a non-topology OP_MSG.
	raw, _ := bson.Marshal(bson.D{
		{Key: "ok", Value: 1.0},
		{Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)}}},
	})
	body := BuildOpMsg(0, raw)
	wireMsg := buildWireMessage(OpMsg, body)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		serverConn.Write(wireMsg)
		serverConn.Close()
	}()

	rw := NewTopologyRewriter(clientConn, "proxy:5555")

	result := make([]byte, len(wireMsg)+64)
	totalRead := 0
	for {
		n, err := rw.Read(result[totalRead:])
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	// Non-topology messages should pass through with same length.
	if totalRead != len(wireMsg) {
		t.Errorf("expected %d bytes, got %d (non-topology should be unchanged)", len(wireMsg), totalRead)
	}
}

func TestTopologyRewriter_PartialRead(t *testing.T) {
	// Verify that partial reads (small buffer) still work correctly.
	raw, _ := bson.Marshal(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"backend:27017"}},
		{Key: "me", Value: "backend:27017"},
		{Key: "ok", Value: 1.0},
	})
	body := BuildOpMsg(0, raw)
	wireMsg := buildWireMessage(OpMsg, body)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		serverConn.Write(wireMsg)
		serverConn.Close()
	}()

	rw := NewTopologyRewriter(clientConn, "proxy:1234")

	// Read in very small chunks to exercise buffering.
	var result []byte
	buf := make([]byte, 8)
	for {
		n, err := rw.Read(buf)
		result = append(result, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	if len(result) < headerSize {
		t.Fatalf("too short: %d bytes", len(result))
	}

	_, doc, err := ParseOpMsgBody(result[headerSize:])
	if err != nil {
		t.Fatalf("ParseOpMsgBody: %v", err)
	}

	var d bson.D
	if err := bson.Unmarshal(doc, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, e := range d {
		if e.Key == "hosts" {
			arr := e.Value.(bson.A)
			if len(arr) != 1 || arr[0] != "proxy:1234" {
				t.Errorf("hosts not rewritten in partial-read: %v", arr)
			}
		}
	}
}

func TestTopologyRewriter_NonOpMsg(t *testing.T) {
	// Non-OP_MSG messages (like OP_REPLY) should pass through unchanged.
	doc, _ := bson.Marshal(bson.D{{Key: "ok", Value: 1.0}})
	body := BuildOpReply(doc)
	wireMsg := buildWireMessage(OpReply, body)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		serverConn.Write(wireMsg)
		serverConn.Close()
	}()

	rw := NewTopologyRewriter(clientConn, "proxy:5555")

	result := make([]byte, len(wireMsg)+64)
	totalRead := 0
	for {
		n, err := rw.Read(result[totalRead:])
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	if totalRead != len(wireMsg) {
		t.Errorf("OP_REPLY should pass through unchanged: %d vs %d", totalRead, len(wireMsg))
	}
}

func TestTopologyRewriter_MultipleMessages(t *testing.T) {
	// Send two messages: one with topology, one without.
	topoRaw, _ := bson.Marshal(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"backend:27017"}},
		{Key: "ok", Value: 1.0},
	})
	normalRaw, _ := bson.Marshal(bson.D{{Key: "ok", Value: 1.0}})

	msg1 := buildWireMessage(OpMsg, BuildOpMsg(0, topoRaw))
	msg2 := buildWireMessage(OpMsg, BuildOpMsg(0, normalRaw))

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		serverConn.Write(msg1)
		serverConn.Write(msg2)
		serverConn.Close()
	}()

	rw := NewTopologyRewriter(clientConn, "proxy:5555")

	// Read first message.
	result1, err := readFullMessage(rw)
	if err != nil {
		t.Fatalf("read msg1: %v", err)
	}

	_, doc1, _ := ParseOpMsgBody(result1[headerSize:])
	var d1 bson.D
	bson.Unmarshal(doc1, &d1)
	for _, e := range d1 {
		if e.Key == "hosts" {
			arr := e.Value.(bson.A)
			if arr[0] != "proxy:5555" {
				t.Errorf("msg1 hosts not rewritten: %v", arr)
			}
		}
	}

	// Read second message.
	result2, err := readFullMessage(rw)
	if err != nil {
		t.Fatalf("read msg2: %v", err)
	}
	if len(result2) != len(msg2) {
		t.Errorf("msg2 should be unchanged: %d vs %d", len(result2), len(msg2))
	}
}

// readFullMessage reads a complete wire message from r.
func readFullMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	msgLen := int(binary.LittleEndian.Uint32(hdr[:]))
	msg := make([]byte, msgLen)
	copy(msg, hdr[:])
	if _, err := io.ReadFull(r, msg[4:]); err != nil {
		return nil, err
	}
	return msg, nil
}
