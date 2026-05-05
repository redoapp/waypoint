package mongowire

import (
	"encoding/binary"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func buildTestOpMsgBody(doc bson.D) []byte {
	raw, err := bson.Marshal(doc)
	if err != nil {
		panic(err)
	}
	body := make([]byte, 4+1+len(raw))
	binary.LittleEndian.PutUint32(body[0:4], 0) // flags
	body[4] = SectionBody
	copy(body[5:], raw)
	return body
}

func parseTestOpMsgBody(t *testing.T, body []byte) bson.D {
	t.Helper()
	_, doc, err := ParseOpMsgBody(body)
	if err != nil {
		t.Fatalf("ParseOpMsgBody: %v", err)
	}
	var d bson.D
	if err := bson.Unmarshal(doc, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return d
}

func TestRewriteTopology_ReplicaSet(t *testing.T) {
	body := buildTestOpMsgBody(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"mongo1.internal:27017", "mongo2.internal:27017", "mongo3.internal:27017"}},
		{Key: "passives", Value: bson.A{"mongo4.internal:27017"}},
		{Key: "arbiters", Value: bson.A{"mongo5.internal:27017"}},
		{Key: "me", Value: "mongo1.internal:27017"},
		{Key: "primary", Value: "mongo1.internal:27017"},
		{Key: "setName", Value: "rs0"},
		{Key: "ok", Value: 1.0},
	})

	rewritten := RewriteTopology(body, "waypoint.tailnet:27017")
	doc := parseTestOpMsgBody(t, rewritten)

	for _, e := range doc {
		switch e.Key {
		case "hosts":
			arr := e.Value.(bson.A)
			if len(arr) != 3 {
				t.Fatalf("expected 3 hosts, got %d", len(arr))
			}
			for i, h := range arr {
				if h != "waypoint.tailnet:27017" {
					t.Errorf("hosts[%d] = %q, want waypoint.tailnet:27017", i, h)
				}
			}
		case "passives":
			arr := e.Value.(bson.A)
			for i, h := range arr {
				if h != "waypoint.tailnet:27017" {
					t.Errorf("passives[%d] = %q, want waypoint.tailnet:27017", i, h)
				}
			}
		case "arbiters":
			arr := e.Value.(bson.A)
			for i, h := range arr {
				if h != "waypoint.tailnet:27017" {
					t.Errorf("arbiters[%d] = %q, want waypoint.tailnet:27017", i, h)
				}
			}
		case "me":
			if e.Value != "waypoint.tailnet:27017" {
				t.Errorf("me = %q, want waypoint.tailnet:27017", e.Value)
			}
		case "primary":
			if e.Value != "waypoint.tailnet:27017" {
				t.Errorf("primary = %q, want waypoint.tailnet:27017", e.Value)
			}
		}
	}
}

func TestRewriteTopology_ReplicaSetWithMap(t *testing.T) {
	body := buildTestOpMsgBody(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"mongo1.internal:27017", "mongo2.internal:27017", "mongo3.internal:27017"}},
		{Key: "me", Value: "mongo2.internal:27017"},
		{Key: "primary", Value: "mongo1.internal:27017"},
		{Key: "setName", Value: "rs0"},
		{Key: "ok", Value: 1.0},
	})

	rewritten := RewriteTopologyWithMap(body, "waypoint-fallback:27017", map[string]string{
		"mongo1.internal:27017": "waypoint:27017",
		"mongo2.internal:27017": "waypoint:27018",
		"mongo3.internal:27017": "waypoint:27019",
	})
	doc := parseTestOpMsgBody(t, rewritten)

	for _, e := range doc {
		switch e.Key {
		case "hosts":
			arr := e.Value.(bson.A)
			want := []string{"waypoint:27017", "waypoint:27018", "waypoint:27019"}
			for i := range want {
				if arr[i] != want[i] {
					t.Errorf("hosts[%d] = %q, want %q", i, arr[i], want[i])
				}
			}
		case "me":
			if e.Value != "waypoint:27018" {
				t.Errorf("me = %q, want waypoint:27018", e.Value)
			}
		case "primary":
			if e.Value != "waypoint:27017" {
				t.Errorf("primary = %q, want waypoint:27017", e.Value)
			}
		}
	}
}

func TestRewriteTopology_ReplicaSetWithMapFallback(t *testing.T) {
	body := buildTestOpMsgBody(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"mongo1.internal:27017", "mongo2.internal:27017"}},
		{Key: "primary", Value: "mongo2.internal:27017"},
		{Key: "ok", Value: 1.0},
	})

	rewritten := RewriteTopologyWithMap(body, "waypoint-fallback:27017", map[string]string{
		"mongo1.internal:27017": "waypoint:27017",
	})
	doc := parseTestOpMsgBody(t, rewritten)

	for _, e := range doc {
		switch e.Key {
		case "hosts":
			arr := e.Value.(bson.A)
			if arr[0] != "waypoint:27017" {
				t.Errorf("hosts[0] = %q, want waypoint:27017", arr[0])
			}
			if arr[1] != "waypoint-fallback:27017" {
				t.Errorf("hosts[1] = %q, want waypoint-fallback:27017", arr[1])
			}
		case "primary":
			if e.Value != "waypoint-fallback:27017" {
				t.Errorf("primary = %q, want waypoint-fallback:27017", e.Value)
			}
		}
	}
}

func TestRewriteTopology_NoTopologyFields(t *testing.T) {
	body := buildTestOpMsgBody(bson.D{
		{Key: "ok", Value: 1.0},
		{Key: "cursor", Value: bson.D{{Key: "id", Value: int64(0)}}},
	})

	rewritten := RewriteTopology(body, "waypoint:27017")

	// Should pass through unchanged.
	if len(rewritten) != len(body) {
		t.Fatalf("expected unchanged body length %d, got %d", len(body), len(rewritten))
	}
}

func TestRewriteTopology_Standalone(t *testing.T) {
	// Standalone mongod response — no hosts field.
	body := buildTestOpMsgBody(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "maxBsonObjectSize", Value: 16777216},
		{Key: "ok", Value: 1.0},
	})

	rewritten := RewriteTopology(body, "waypoint:27017")

	// Should pass through unchanged (no "hosts" key).
	if len(rewritten) != len(body) {
		t.Fatalf("expected unchanged body length %d, got %d", len(body), len(rewritten))
	}
}

func TestRewriteTopology_WithChecksum(t *testing.T) {
	// Build body with FlagChecksumPresent and trailing 4-byte CRC.
	raw, _ := bson.Marshal(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"internal:27017"}},
		{Key: "me", Value: "internal:27017"},
		{Key: "ok", Value: 1.0},
	})
	body := make([]byte, 4+1+len(raw)+4) // +4 for checksum
	binary.LittleEndian.PutUint32(body[0:4], FlagChecksumPresent)
	body[4] = SectionBody
	copy(body[5:5+len(raw)], raw)
	binary.LittleEndian.PutUint32(body[len(body)-4:], 0x12345678) // fake CRC

	rewritten := RewriteTopology(body, "proxy:9999")

	// The checksum flag should be cleared (checksum is stripped).
	flags := binary.LittleEndian.Uint32(rewritten[0:4])
	if flags&FlagChecksumPresent != 0 {
		t.Error("FlagChecksumPresent should be cleared after rewrite")
	}

	// The document should still parse correctly.
	doc := parseTestOpMsgBody(t, rewritten)
	for _, e := range doc {
		if e.Key == "hosts" {
			arr := e.Value.(bson.A)
			if len(arr) != 1 || arr[0] != "proxy:9999" {
				t.Errorf("hosts not rewritten: %v", arr)
			}
		}
		if e.Key == "me" && e.Value != "proxy:9999" {
			t.Errorf("me not rewritten: %v", e.Value)
		}
	}
}

func TestRewriteTopology_ChecksumNoTopology(t *testing.T) {
	// Body with checksum but no topology fields — should pass through unchanged.
	raw, _ := bson.Marshal(bson.D{
		{Key: "ok", Value: 1.0},
	})
	body := make([]byte, 4+1+len(raw)+4)
	binary.LittleEndian.PutUint32(body[0:4], FlagChecksumPresent)
	body[4] = SectionBody
	copy(body[5:5+len(raw)], raw)
	binary.LittleEndian.PutUint32(body[len(body)-4:], 0xAABBCCDD)

	rewritten := RewriteTopology(body, "proxy:9999")

	// No topology fields → body should be unchanged (including checksum).
	if len(rewritten) != len(body) {
		t.Fatalf("expected unchanged length %d, got %d", len(body), len(rewritten))
	}
}

func TestRewriteTopology_PreservesOtherFields(t *testing.T) {
	body := buildTestOpMsgBody(bson.D{
		{Key: "ismaster", Value: true},
		{Key: "hosts", Value: bson.A{"internal:27017"}},
		{Key: "me", Value: "internal:27017"},
		{Key: "setName", Value: "rs0"},
		{Key: "maxBsonObjectSize", Value: 16777216},
		{Key: "ok", Value: 1.0},
	})

	rewritten := RewriteTopology(body, "proxy:5555")
	doc := parseTestOpMsgBody(t, rewritten)

	for _, e := range doc {
		switch e.Key {
		case "setName":
			if e.Value != "rs0" {
				t.Errorf("setName changed: %v", e.Value)
			}
		case "maxBsonObjectSize":
			if e.Value != int32(16777216) {
				t.Errorf("maxBsonObjectSize changed: %v", e.Value)
			}
		case "ok":
			if e.Value != 1.0 {
				t.Errorf("ok changed: %v", e.Value)
			}
		case "ismaster":
			if e.Value != true {
				t.Errorf("ismaster changed: %v", e.Value)
			}
		}
	}
}
