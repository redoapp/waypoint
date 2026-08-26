package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
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

func TestFormatUsernameWithScope(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_"}
	got := p.formatUsernameWithScope("user@example.com", "laptop", "mydb", "preset_readonly")
	want := "wp_user_example_com_laptop_mydb_preset_readonly"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNewProvisioner_DefaultPrefix(t *testing.T) {
	p := NewProvisioner("admin", "pass", "postgres", "localhost:5432", "test-listener", "", false, true, "", nil, nil, nil, nil)
	if p.userPrefix != "wp_" {
		t.Errorf("expected default prefix wp_, got %q", p.userPrefix)
	}
}

func TestNewProvisioner_CustomPrefix(t *testing.T) {
	p := NewProvisioner("admin", "pass", "postgres", "localhost:5432", "test-listener", "custom_", false, true, "", nil, nil, nil, nil)
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

func TestFormatUsername_IncludesListener(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	got := p.formatUsername("alice@example.com", "alice-laptop", "app_db")

	want := "wp_pg_main_alice_example_com_alice_laptop_app_db"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatUsername_ListenersGetDistinctRoles(t *testing.T) {
	// The reason the listener is in the name: two listeners over one backend
	// can carry different capability grants, and a shared role would let
	// whichever provisioned last set the privileges for both.
	wire := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	web := &Provisioner{userPrefix: "wp_", listener: "console"}

	a := wire.formatUsername("alice@example.com", "laptop", "app_db")
	b := web.formatUsername("alice@example.com", "laptop", "app_db")
	if a == b {
		t.Fatalf("both listeners resolved to %q", a)
	}
}

func TestFormatUsername_ListenerComesBeforeScope(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	got := p.formatUsernameWithScope("alice@example.com", "laptop", "app_db", "preset_readonly")

	want := "wp_pg_main_alice_example_com_laptop_app_db_preset_readonly"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatUsername_EmptyListenerKeepsLegacyName(t *testing.T) {
	// An unset listener degrades to the pre-listener name rather than
	// producing a trailing underscore. Config requires a listener name, so
	// this only arises in tests.
	p := &Provisioner{userPrefix: "wp_"}
	got := p.formatUsername("alice@example.com", "laptop", "app_db")

	if want := "wp_alice_example_com_laptop_app_db"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFormatUsername_ListenersStayDistinctAfterTruncation(t *testing.T) {
	// Long inputs truncate to 63 bytes with a hash suffix. The hash covers
	// the full name including the listener, so listeners that collide once
	// truncated still resolve to different roles.
	longLogin := "very.long.email.address.for.testing@extremely.long.domain.example.com"
	longNode := "super-extremely-long-node-hostname-that-goes-on"
	longDB := "very_long_database_name_that_exceeds_normal_limits"

	a := (&Provisioner{userPrefix: "wp_", listener: "listener-alpha"}).
		formatUsername(longLogin, longNode, longDB)
	b := (&Provisioner{userPrefix: "wp_", listener: "listener-beta"}).
		formatUsername(longLogin, longNode, longDB)

	for _, name := range []string{a, b} {
		if len(name) > 63 {
			t.Errorf("name exceeds the postgres identifier limit at %d: %q", len(name), name)
		}
	}
	if a == b {
		t.Errorf("truncation collapsed two listeners onto %q", a)
	}
	// The listener has to survive truncation, not merely leave the names
	// distinct via the hash — otherwise a role in pg_stat_activity cannot be
	// attributed to the listener that created it.
	if !strings.HasPrefix(a, "wp_listener_alpha_") {
		t.Errorf("listener did not survive truncation: %q", a)
	}
	if !strings.HasPrefix(b, "wp_listener_beta_") {
		t.Errorf("listener did not survive truncation: %q", b)
	}
}

func TestTruncateWithHash_Shape(t *testing.T) {
	// 52 readable characters, an underscore, then 10 hex characters of
	// digest — filling the 63-byte Postgres identifier limit exactly.
	name := strings.Repeat("a", 200)
	got := truncateWithHash(name, maxPGIdentifier)

	if len(got) != maxPGIdentifier {
		t.Fatalf("len = %d, want %d", len(got), maxPGIdentifier)
	}
	kept, sep, suffix := got[:52], got[52], got[53:]
	if kept != strings.Repeat("a", 52) {
		t.Errorf("kept portion = %q", kept)
	}
	if sep != '_' {
		t.Errorf("separator = %q, want an underscore", string(sep))
	}
	if len(suffix) != 10 {
		t.Errorf("suffix = %q, want 10 characters", suffix)
	}
	for _, c := range suffix {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("suffix %q is not hex", suffix)
			break
		}
	}
}

func TestTruncateWithHash_HashesOnlyTheDiscardedRemainder(t *testing.T) {
	// Two names agreeing on the kept prefix and differing only past it must
	// still land on different identifiers — this is the case the hash exists
	// for, and the reason hashing the remainder alone is sufficient.
	prefix := strings.Repeat("a", 52)
	a := truncateWithHash(prefix+"first-remainder", maxPGIdentifier)
	b := truncateWithHash(prefix+"second-remainder", maxPGIdentifier)

	if a == b {
		t.Fatalf("names differing only past the cut collapsed onto %q", a)
	}
	if a[:52] != b[:52] {
		t.Errorf("kept portions should be identical: %q vs %q", a[:52], b[:52])
	}

	// The suffix is a digest of the discarded remainder, so it is exactly
	// what a caller could recompute.
	sum := sha256.Sum256([]byte("first-remainder"))
	if want := hex.EncodeToString(sum[:])[:10]; a[53:] != want {
		t.Errorf("suffix = %q, want the digest of the remainder %q", a[53:], want)
	}
}

func TestTruncateWithHash_Deterministic(t *testing.T) {
	// Two equal strings built independently, so this compares values rather
	// than the same expression twice. Role names have to be stable across
	// processes and restarts, or a reconnect would provision a second role.
	a := truncateWithHash(strings.Repeat("z", 120), maxPGIdentifier)
	b := truncateWithHash(strings.Repeat("z", 60)+strings.Repeat("z", 60), maxPGIdentifier)
	if a != b {
		t.Errorf("truncation is not stable: %q vs %q", a, b)
	}

	// Pinned, so a change to the scheme has to be deliberate.
	const want = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz_46aaf07558"
	if a != want {
		t.Errorf("truncation changed shape:\n got %q\nwant %q", a, want)
	}
}

func TestTruncateWithHash_LeavesShortNamesAlone(t *testing.T) {
	for _, name := range []string{"", "wp_alice_laptop_db", strings.Repeat("a", maxPGIdentifier)} {
		if got := truncateWithHash(name, maxPGIdentifier); got != name {
			t.Errorf("truncateWithHash(%q) = %q, want it unchanged", name, got)
		}
	}
}

func TestTruncateWithHash_DoesNotSplitARune(t *testing.T) {
	// user_prefix is not sanitized, so it can carry multi-byte runes.
	// Slicing one in half would emit invalid UTF-8.
	name := strings.Repeat("é", 100)
	got := truncateWithHash(name, maxPGIdentifier)

	if len(got) > maxPGIdentifier {
		t.Errorf("len = %d, want <= %d", len(got), maxPGIdentifier)
	}
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got)
	}
}

func TestTruncateWithHash_MongoLimit(t *testing.T) {
	got := truncateWithHash(strings.Repeat("a", 300), maxMongoIdentifier)
	if len(got) != maxMongoIdentifier {
		t.Fatalf("len = %d, want %d", len(got), maxMongoIdentifier)
	}
	if got[117] != '_' {
		t.Errorf("separator = %q, want an underscore", string(got[117]))
	}
	if len(got[118:]) != 10 {
		t.Errorf("suffix = %q, want 10 characters", got[118:])
	}
}

// captureLogs returns a logger writing JSON records into buf.
func captureLogs(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func decodeLogs(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

func TestFormatUsername_LogsTruncationForCrossReference(t *testing.T) {
	var buf bytes.Buffer
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main", logger: captureLogs(&buf)}

	longLogin := "very.long.email.address.for.testing@extremely.long.domain.example.com"
	got := p.formatUsername(longLogin, "super-long-node-hostname", "some_database")
	if len(got) != maxPGIdentifier {
		t.Fatalf("expected a truncated name, got %q (%d bytes)", got, len(got))
	}

	recs := decodeLogs(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("expected one log record, got %d", len(recs))
	}
	rec := recs[0]

	// The truncated name is what shows up in pg_stat_activity; the original
	// is what it has to be traced back to.
	if rec["name"] != got {
		t.Errorf("logged name = %v, want %q", rec["name"], got)
	}
	original, _ := rec["original"].(string)
	if !strings.Contains(original, "very_long_email_address") {
		t.Errorf("logged original = %q, does not carry the full name", original)
	}
	if len(original) <= maxPGIdentifier {
		t.Errorf("logged original is %d bytes; it should be the untruncated name", len(original))
	}

	// dropped must be exactly the text the hash was computed over, so the
	// record is enough on its own to reproduce the name.
	dropped, _ := rec["dropped"].(string)
	if dropped == "" {
		t.Fatal("no dropped text logged")
	}
	sum := sha256.Sum256([]byte(dropped))
	if want := hex.EncodeToString(sum[:])[:truncationHashLen]; !strings.HasSuffix(got, want) {
		t.Errorf("hash of the logged dropped text (%s) is not the suffix of %q", want, got)
	}
	if kept := got[:len(got)-truncationHashLen-1]; kept+dropped != original {
		t.Errorf("kept + dropped != original:\n  kept=%q\n  dropped=%q\n  original=%q", kept, dropped, original)
	}
}

func TestFormatUsername_LogsTruncationOncePerName(t *testing.T) {
	var buf bytes.Buffer
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main", logger: captureLogs(&buf)}

	longLogin := "very.long.email.address.for.testing@extremely.long.domain.example.com"
	// A role name is derived on every connection, so logging each time would
	// bury the log for a user whose name always truncates.
	for range 5 {
		p.formatUsername(longLogin, "super-long-node-hostname", "some_database")
	}
	if recs := decodeLogs(t, &buf); len(recs) != 1 {
		t.Errorf("expected one record for five derivations, got %d", len(recs))
	}

	// A different name is a different fact and gets its own record.
	p.formatUsername(longLogin, "another-very-long-node-hostname", "some_database")
	if recs := decodeLogs(t, &buf); len(recs) != 2 {
		t.Errorf("expected a second record for a different name, got %d", len(recs))
	}
}

func TestFormatUsername_NoLogWhenNameFits(t *testing.T) {
	var buf bytes.Buffer
	p := &Provisioner{userPrefix: "wp_", listener: "pg", logger: captureLogs(&buf)}

	if got := p.formatUsername("alice@example.com", "laptop", "appdb"); len(got) > maxPGIdentifier {
		t.Fatalf("name unexpectedly truncated: %q", got)
	}
	if buf.Len() != 0 {
		t.Errorf("logged despite no truncation: %s", buf.String())
	}
}

func TestFormatUsername_NilLoggerDoesNotPanic(t *testing.T) {
	// Several call sites construct a provisioner without a logger.
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	longLogin := "very.long.email.address.for.testing@extremely.long.domain.example.com"
	_ = p.formatUsername(longLogin, "super-long-node-hostname", "some_database")
}

func TestMongoFormatUsername_LogsTruncation(t *testing.T) {
	var buf bytes.Buffer
	p := &MongoProvisioner{userPrefix: "wp_", listener: "mongo-main", logger: captureLogs(&buf)}

	longLogin := strings.Repeat("very.long.email.address.for.testing@example.com.", 4)
	got := p.formatUsername(longLogin, "super-long-node-hostname")
	if len(got) != maxMongoIdentifier {
		t.Fatalf("expected a truncated name, got %d bytes", len(got))
	}
	recs := decodeLogs(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("expected one log record, got %d", len(recs))
	}
	if recs[0]["name"] != got {
		t.Errorf("logged name = %v, want %q", recs[0]["name"], got)
	}
}
