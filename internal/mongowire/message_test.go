package mongowire

import (
	"encoding/binary"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestParseOpMsgBody_Basic(t *testing.T) {
	doc, _ := bson.Marshal(bson.D{{Key: "ok", Value: 1.0}})
	body := make([]byte, 4+1+len(doc))
	binary.LittleEndian.PutUint32(body[0:4], 0)
	body[4] = SectionBody
	copy(body[5:], doc)

	flags, parsed, err := ParseOpMsgBody(body)
	if err != nil {
		t.Fatalf("ParseOpMsgBody: %v", err)
	}
	if flags != 0 {
		t.Errorf("flags = %d, want 0", flags)
	}
	if len(parsed) != len(doc) {
		t.Errorf("doc len = %d, want %d", len(parsed), len(doc))
	}
}

func TestParseOpMsgBody_WithChecksum(t *testing.T) {
	// When FlagChecksumPresent is set, there are 4 trailing bytes after sections.
	// ParseOpMsgBody should still find the document correctly.
	doc, _ := bson.Marshal(bson.D{{Key: "hello", Value: 1}})
	body := make([]byte, 4+1+len(doc)+4) // +4 for checksum
	binary.LittleEndian.PutUint32(body[0:4], FlagChecksumPresent)
	body[4] = SectionBody
	copy(body[5:], doc)
	// Last 4 bytes are a fake checksum (doesn't matter for parsing).
	binary.LittleEndian.PutUint32(body[len(body)-4:], 0xDEADBEEF)

	flags, parsed, err := ParseOpMsgBody(body)
	if err != nil {
		t.Fatalf("ParseOpMsgBody with checksum: %v", err)
	}
	if flags != FlagChecksumPresent {
		t.Errorf("flags = %d, want %d", flags, FlagChecksumPresent)
	}
	if len(parsed) != len(doc) {
		t.Errorf("doc len = %d, want %d", len(parsed), len(doc))
	}
}

func TestParseOpMsgBody_WithDocumentSequence(t *testing.T) {
	// Build: flags(4) + kind-1 section + kind-0 section
	doc, _ := bson.Marshal(bson.D{{Key: "insert", Value: "coll"}, {Key: "$db", Value: "test"}})

	// Kind-1 (document sequence): size(4) + identifier(cstring) + documents
	seqDoc, _ := bson.Marshal(bson.D{{Key: "x", Value: 1}})
	identifier := append([]byte("documents"), 0) // null-terminated
	seqPayload := append(identifier, seqDoc...)
	seqSize := 4 + len(seqPayload) // 4 bytes for the size itself

	seqSection := make([]byte, seqSize)
	binary.LittleEndian.PutUint32(seqSection[0:4], uint32(seqSize))
	copy(seqSection[4:], seqPayload)

	// Full body: flags + kind-1 section + kind-0 section
	body := make([]byte, 4+1+len(seqSection)+1+len(doc))
	binary.LittleEndian.PutUint32(body[0:4], 0) // flags
	body[4] = SectionDocumentSequence
	copy(body[5:5+len(seqSection)], seqSection)
	body[5+len(seqSection)] = SectionBody
	copy(body[5+len(seqSection)+1:], doc)

	_, parsed, err := ParseOpMsgBody(body)
	if err != nil {
		t.Fatalf("ParseOpMsgBody with doc sequence: %v", err)
	}

	cmdName, _ := CommandName(parsed)
	if cmdName != "insert" {
		t.Errorf("command = %q, want insert", cmdName)
	}
}

func TestParseOpMsgBody_TooShort(t *testing.T) {
	_, _, err := ParseOpMsgBody([]byte{0, 0})
	if err == nil {
		t.Fatal("expected error for short body")
	}
}

func TestParseOpMsgBody_UnknownSectionKind(t *testing.T) {
	body := make([]byte, 6)
	binary.LittleEndian.PutUint32(body[0:4], 0) // flags
	body[4] = 42                                // unknown kind
	body[5] = 0

	_, _, err := ParseOpMsgBody(body)
	if err == nil {
		t.Fatal("expected error for unknown section kind")
	}
}

func TestParseOpQueryBody_Basic(t *testing.T) {
	doc, _ := bson.Marshal(bson.D{{Key: "isMaster", Value: 1}})
	// flags(4) + collection(cstring) + skip(4) + return(4) + doc
	collection := append([]byte("admin.$cmd"), 0)
	body := make([]byte, 4+len(collection)+8+len(doc))
	// flags at 0:4 are zero
	copy(body[4:], collection)
	// skip + return at offset after collection (zeros are fine)
	copy(body[4+len(collection)+8:], doc)

	parsed, err := ParseOpQueryBody(body)
	if err != nil {
		t.Fatalf("ParseOpQueryBody: %v", err)
	}

	name, _ := CommandName(parsed)
	if name != "isMaster" {
		t.Errorf("command = %q, want isMaster", name)
	}
}

func TestParseOpQueryBody_TooShort(t *testing.T) {
	_, err := ParseOpQueryBody([]byte{0, 0, 0})
	if err == nil {
		t.Fatal("expected error for short body")
	}
}

func TestParseOpQueryBody_NoTerminator(t *testing.T) {
	// Collection name without null terminator.
	body := make([]byte, 20)
	for i := 4; i < 20; i++ {
		body[i] = 'a' // all non-null
	}
	_, err := ParseOpQueryBody(body)
	if err == nil {
		t.Fatal("expected error for unterminated collection name")
	}
}

func TestBuildOpMsg_RoundTrip(t *testing.T) {
	doc, _ := bson.Marshal(bson.D{{Key: "ok", Value: 1.0}})
	body := BuildOpMsg(0, doc)

	flags, parsed, err := ParseOpMsgBody(body)
	if err != nil {
		t.Fatalf("round-trip ParseOpMsgBody: %v", err)
	}
	if flags != 0 {
		t.Errorf("flags = %d, want 0", flags)
	}
	if len(parsed) != len(doc) {
		t.Errorf("doc len = %d, want %d", len(parsed), len(doc))
	}
}

func TestCommandName_Empty(t *testing.T) {
	doc, _ := bson.Marshal(bson.D{})
	_, err := CommandName(doc)
	if err == nil {
		t.Fatal("expected error for empty document")
	}
}

func TestCommandDB(t *testing.T) {
	doc, _ := bson.Marshal(bson.D{{Key: "hello", Value: 1}, {Key: "$db", Value: "admin"}})
	if db := CommandDB(doc); db != "admin" {
		t.Errorf("CommandDB = %q, want admin", db)
	}
}

func TestCommandDB_Missing(t *testing.T) {
	doc, _ := bson.Marshal(bson.D{{Key: "hello", Value: 1}})
	if db := CommandDB(doc); db != "" {
		t.Errorf("CommandDB = %q, want empty", db)
	}
}

func TestExtractSASLPayload_Error(t *testing.T) {
	doc, _ := bson.Marshal(bson.D{
		{Key: "ok", Value: 0.0},
		{Key: "errmsg", Value: "auth failed"},
	})
	_, _, _, err := ExtractSASLPayload(doc)
	if err == nil {
		t.Fatal("expected error for failed SASL response")
	}
}
