package provision

import (
	"strings"
	"testing"
)

func TestMongoFormatUsername_Basic(t *testing.T) {
	p := &MongoProvisioner{userPrefix: "wp_"}
	name := p.formatUsername("alice@example.com", "my-node")
	if !strings.HasPrefix(name, "wp_") {
		t.Errorf("expected wp_ prefix, got %q", name)
	}
	if strings.Contains(name, "@") || strings.Contains(name, "-") {
		t.Errorf("expected sanitized name, got %q", name)
	}
}

func TestMongoFormatUsername_Truncation(t *testing.T) {
	p := &MongoProvisioner{userPrefix: "wp_"}
	longLogin := strings.Repeat("a", 100) + "@example.com"
	longNode := strings.Repeat("b", 50)
	name := p.formatUsername(longLogin, longNode)

	if len(name) > 128 {
		t.Errorf("name too long: %d chars", len(name))
	}
}

func TestMongoFormatUsername_TruncationHashUniqueness(t *testing.T) {
	p := &MongoProvisioner{userPrefix: "wp_"}

	// Two different long usernames that would truncate to the same prefix.
	longLogin1 := strings.Repeat("a", 100) + "1@example.com"
	longLogin2 := strings.Repeat("a", 100) + "2@example.com"
	node := strings.Repeat("n", 30)

	name1 := p.formatUsername(longLogin1, node)
	name2 := p.formatUsername(longLogin2, node)

	if name1 == name2 {
		t.Errorf("different logins should produce different names after truncation: %q", name1)
	}
	if len(name1) > 128 || len(name2) > 128 {
		t.Errorf("names should be <= 128 chars: %d, %d", len(name1), len(name2))
	}
}

func TestMongoFormatUsername_ShortNoHash(t *testing.T) {
	p := &MongoProvisioner{userPrefix: "wp_"}
	name := p.formatUsername("bob@test.com", "node1")

	// Short names should not have a hash suffix.
	if len(name) > 128 {
		t.Errorf("short name should not be truncated: %q", name)
	}
	// Should be: wp_bob_test_com_node1
	if !strings.HasPrefix(name, "wp_bob") {
		t.Errorf("unexpected prefix: %q", name)
	}
}

func TestMongoAdminURI_Standalone(t *testing.T) {
	uri := mongoAdminURI("admin", "pass", []string{"mongo1:27017"}, "", "admin", false)
	if uri != "mongodb://admin:pass@mongo1:27017/admin?directConnection=true" {
		t.Fatalf("uri = %q", uri)
	}
}

func TestMongoAdminURI_ReplicaSet(t *testing.T) {
	uri := mongoAdminURI("admin", "pass", []string{"mongo1:27017", "mongo2:27017", "mongo3:27017"}, "rs0", "admin", true)
	want := "mongodb://admin:pass@mongo1:27017,mongo2:27017,mongo3:27017/admin?replicaSet=rs0&tls=true"
	if uri != want {
		t.Fatalf("uri = %q, want %q", uri, want)
	}
}

func TestExpandMongoPresets_Readonly(t *testing.T) {
	roles, err := ExpandMongoPresets([]string{"readonly"}, "mydb")
	if err != nil {
		t.Fatalf("ExpandMongoPresets: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(roles))
	}
	if roles[0].Role != "read" || roles[0].DB != "mydb" {
		t.Errorf("unexpected role: %+v", roles[0])
	}
}

func TestExpandMongoPresets_ReadWrite(t *testing.T) {
	roles, err := ExpandMongoPresets([]string{"readwrite"}, "mydb")
	if err != nil {
		t.Fatalf("ExpandMongoPresets: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != "readWrite" {
		t.Errorf("unexpected: %+v", roles)
	}
}

func TestExpandMongoPresets_Admin(t *testing.T) {
	roles, err := ExpandMongoPresets([]string{"admin"}, "mydb")
	if err != nil {
		t.Fatalf("ExpandMongoPresets: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != "dbOwner" {
		t.Errorf("unexpected: %+v", roles)
	}
}

func TestExpandMongoPresets_Invalid(t *testing.T) {
	_, err := ExpandMongoPresets([]string{"superadmin"}, "mydb")
	if err == nil {
		t.Fatal("expected error for invalid preset")
	}
}

func TestExpandMongoPresets_Empty(t *testing.T) {
	roles, err := ExpandMongoPresets([]string{}, "mydb")
	if err != nil {
		t.Fatalf("ExpandMongoPresets: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(roles))
	}
}

func TestExpandMongoPresets_Dedup(t *testing.T) {
	roles, err := ExpandMongoPresets([]string{"readonly", "readonly"}, "mydb")
	if err != nil {
		t.Fatalf("ExpandMongoPresets: %v", err)
	}
	if len(roles) != 1 {
		t.Errorf("expected dedup to 1 role, got %d", len(roles))
	}
}

func TestExpandMongoPresets_Multiple(t *testing.T) {
	roles, err := ExpandMongoPresets([]string{"readonly", "readwrite"}, "mydb")
	if err != nil {
		t.Fatalf("ExpandMongoPresets: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestExpandMongoPresets_CaseInsensitive(t *testing.T) {
	roles, err := ExpandMongoPresets([]string{"ReadOnly"}, "mydb")
	if err != nil {
		t.Fatalf("ExpandMongoPresets: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != "read" {
		t.Errorf("unexpected: %+v", roles)
	}
}
