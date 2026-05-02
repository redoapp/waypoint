package provision

import (
	"strings"
	"testing"
)

func TestExpandPresets_Readonly(t *testing.T) {
	frags, err := ExpandPresets([]string{"readonly"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"USAGE ON SCHEMA public",
		"SELECT ON ALL TABLES IN SCHEMA public",
		"SELECT ON ALL SEQUENCES IN SCHEMA public",
	}
	if len(frags) != len(expected) {
		t.Fatalf("expected %d fragments, got %d: %v", len(expected), len(frags), frags)
	}
	for i, f := range frags {
		if f != expected[i] {
			t.Errorf("fragment[%d] = %q, want %q", i, f, expected[i])
		}
	}
}

func TestExpandPresets_Readwrite(t *testing.T) {
	frags, err := ExpandPresets([]string{"readwrite"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 5 {
		t.Fatalf("expected 5 fragments for readwrite, got %d: %v", len(frags), frags)
	}
	// Should include readonly fragments plus write ones.
	hasSelect := false
	hasInsert := false
	for _, f := range frags {
		if strings.Contains(f, "SELECT ON ALL TABLES") {
			hasSelect = true
		}
		if strings.Contains(f, "INSERT") {
			hasInsert = true
		}
	}
	if !hasSelect || !hasInsert {
		t.Errorf("readwrite should include SELECT and INSERT grants: %v", frags)
	}
}

func TestExpandPresets_Admin(t *testing.T) {
	frags, err := ExpandPresets([]string{"admin"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 3 {
		t.Fatalf("expected 3 fragments for admin, got %d: %v", len(frags), frags)
	}
	hasAll := false
	for _, f := range frags {
		if strings.Contains(f, "ALL PRIVILEGES") {
			hasAll = true
			break
		}
	}
	if !hasAll {
		t.Error("admin should include ALL PRIVILEGES")
	}
}

func TestExpandPresets_CustomSchemas(t *testing.T) {
	frags, err := ExpandPresets([]string{"readonly"}, []string{"public", "analytics"})
	if err != nil {
		t.Fatal(err)
	}
	// 3 templates × 2 schemas = 6
	if len(frags) != 6 {
		t.Fatalf("expected 6 fragments, got %d: %v", len(frags), frags)
	}
	hasPublic := false
	hasAnalytics := false
	for _, f := range frags {
		if strings.Contains(f, "public") {
			hasPublic = true
		}
		if strings.Contains(f, "analytics") {
			hasAnalytics = true
		}
	}
	if !hasPublic || !hasAnalytics {
		t.Error("should have fragments for both schemas")
	}
}

func TestExpandPresets_InvalidPreset(t *testing.T) {
	_, err := ExpandPresets([]string{"select"}, nil)
	if err == nil {
		t.Fatal("expected error for invalid preset")
	}
	if !strings.Contains(err.Error(), "did you mean") {
		t.Errorf("expected hint in error, got: %v", err)
	}
}

func TestExpandPresets_OldStyleFragment(t *testing.T) {
	_, err := ExpandPresets([]string{"SELECT ON ALL TABLES IN SCHEMA public"}, nil)
	if err == nil {
		t.Fatal("expected error for old-style fragment")
	}
	if !strings.Contains(err.Error(), "preset names only") {
		t.Errorf("expected preset-only hint, got: %v", err)
	}
}

func TestExpandPresets_InvalidSchema(t *testing.T) {
	_, err := ExpandPresets([]string{"readonly"}, []string{"public; DROP TABLE"})
	if err == nil {
		t.Fatal("expected error for invalid schema name")
	}
	if !strings.Contains(err.Error(), "invalid schema name") {
		t.Errorf("expected schema error, got: %v", err)
	}
}

func TestExpandPresets_CaseInsensitive(t *testing.T) {
	frags, err := ExpandPresets([]string{"ReadOnly"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 3 {
		t.Fatalf("expected 3 fragments, got %d", len(frags))
	}
}

func TestExpandPresets_NoDuplicates(t *testing.T) {
	// readwrite includes readonly fragments; requesting both shouldn't duplicate.
	frags, err := ExpandPresets([]string{"readonly", "readwrite"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, f := range frags {
		if seen[f] {
			t.Errorf("duplicate fragment: %q", f)
		}
		seen[f] = true
	}
}
