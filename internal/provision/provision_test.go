package provision

import (
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"alice", "alice"},
		{"Alice", "alice"},
		{"alice@example.com", "alice_example_com"},
		{"ALICE@EXAMPLE.COM", "alice_example_com"},
		{"alice-laptop.ts.net", "alice_laptop_ts_net"},
		{"user.name+tag", "user_name_tag"},
		{"123", "123"},
		{"a b c", "a_b_c"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitize(tt.input)
			if got != tt.want {
				t.Errorf("sanitize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatUsername_Basic(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_"}
	got := p.formatUsername("alice@example.com", "alice-laptop", "app_db")

	if !strings.HasPrefix(got, "wp_") {
		t.Errorf("expected wp_ prefix, got %q", got)
	}
	if got != "wp_alice_example_com_alice_laptop_app_db" {
		t.Errorf("got %q", got)
	}
}

func TestFormatUsername_NodeWithDomain(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_"}
	got := p.formatUsername("bob@corp.com", "bob-desktop.tail12345.ts.net", "mydb")

	// Should only use first segment of node name.
	if !strings.Contains(got, "bob_desktop") {
		t.Errorf("expected 'bob_desktop' in name, got %q", got)
	}
	if strings.Contains(got, "tail12345") {
		t.Errorf("should not contain domain parts, got %q", got)
	}
}

func TestFormatUsername_Truncation(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_"}

	// Create inputs that would exceed 63 chars.
	longLogin := "very.long.email.address.for.testing@extremely.long.domain.example.com"
	longNode := "super-extremely-long-node-hostname-that-goes-on-and-on"
	longDB := "very_long_database_name_that_exceeds_normal_limits"

	got := p.formatUsername(longLogin, longNode, longDB)

	if len(got) > 63 {
		t.Errorf("expected <=63 chars, got %d: %q", len(got), got)
	}
	if !strings.HasPrefix(got, "wp_") {
		t.Errorf("expected wp_ prefix, got %q", got)
	}
}

func TestFormatUsername_TruncationDeterministic(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_"}
	longLogin := "very.long.email@extremely.long.domain.example.com"
	longNode := "super-long-node"
	longDB := "very_long_database_name_that_exceeds_limits_by_a_lot"

	got1 := p.formatUsername(longLogin, longNode, longDB)
	got2 := p.formatUsername(longLogin, longNode, longDB)

	if got1 != got2 {
		t.Errorf("truncation not deterministic: %q vs %q", got1, got2)
	}
}

func TestFormatUsername_TruncationUnique(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_"}

	// Two inputs that differ only at the end (which gets truncated).
	got1 := p.formatUsername(
		"user@domain.com",
		"node",
		strings.Repeat("a", 60)+"_different1",
	)
	got2 := p.formatUsername(
		"user@domain.com",
		"node",
		strings.Repeat("a", 60)+"_different2",
	)

	if got1 == got2 {
		t.Errorf("hash suffix should make truncated names unique: %q == %q", got1, got2)
	}
}

func TestFormatUsername_ShortEnough(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_"}
	got := p.formatUsername("a@b.com", "node", "db")

	// Short enough, should not have hash suffix.
	if len(got) > 63 {
		t.Errorf("expected <=63 chars, got %d", len(got))
	}
	if got != "wp_a_b_com_node_db" {
		t.Errorf("got %q", got)
	}
}

func TestFormatUsername_DefaultPrefix(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_"}
	got := p.formatUsername("user@example.com", "laptop", "mydb")
	if !strings.HasPrefix(got, "wp_") {
		t.Errorf("expected wp_ prefix, got %q", got)
	}
}

func TestFormatUsername_CustomPrefix(t *testing.T) {
	p := &Provisioner{userPrefix: "custom_"}
	got := p.formatUsername("user@example.com", "laptop", "mydb")
	if !strings.HasPrefix(got, "custom_") {
		t.Errorf("expected custom_ prefix, got %q", got)
	}
}

func TestNewProvisioner_DefaultPrefix(t *testing.T) {
	p := NewProvisioner("admin", "pass", "postgres", "localhost:5432", "", nil, nil, nil, nil)
	if p.userPrefix != "wp_" {
		t.Errorf("expected default prefix wp_, got %q", p.userPrefix)
	}
}

func TestNewProvisioner_CustomPrefix(t *testing.T) {
	p := NewProvisioner("admin", "pass", "postgres", "localhost:5432", "custom_", nil, nil, nil, nil)
	if p.userPrefix != "custom_" {
		t.Errorf("expected custom_, got %q", p.userPrefix)
	}
}

func TestQuoteLiteral(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"hello", "'hello'"},
		{"it's", "'it''s'"},
		{"a'b'c", "'a''b''c'"},
		{"", "''"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := quoteLiteral(tt.input)
			if got != tt.want {
				t.Errorf("quoteLiteral(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGeneratePassword(t *testing.T) {
	p1 := generatePassword()
	p2 := generatePassword()

	if len(p1) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected 64 hex chars, got %d", len(p1))
	}
	if p1 == p2 {
		t.Error("passwords should be unique")
	}
}
