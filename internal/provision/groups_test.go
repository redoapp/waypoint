package provision

import (
	"strings"
	"testing"

	"github.com/redoapp/waypoint/internal/auth"
)

func TestCanonicalPerms_SetSemantics(t *testing.T) {
	a := &auth.DBPermissions{
		Permissions: []string{"readwrite", "readonly"},
		Schemas:     []string{"public", "audit"},
	}
	b := &auth.DBPermissions{
		Permissions: []string{"readonly", "readwrite"},
		Schemas:     []string{"audit", "public"},
	}
	if canonicalPerms(a) != canonicalPerms(b) {
		t.Fatalf("permission set ordering should not affect canonical form:\n  a=%s\n  b=%s",
			canonicalPerms(a), canonicalPerms(b))
	}
}

func TestCanonicalPerms_SQLOrderMatters(t *testing.T) {
	a := &auth.DBPermissions{
		SQL: []string{
			"GRANT SELECT ON public.foo TO {{.Role}}",
			"REVOKE SELECT ON public.foo FROM {{.Role}}",
		},
	}
	b := &auth.DBPermissions{
		SQL: []string{
			"REVOKE SELECT ON public.foo FROM {{.Role}}",
			"GRANT SELECT ON public.foo TO {{.Role}}",
		},
	}
	if canonicalPerms(a) == canonicalPerms(b) {
		t.Fatal("SQL fragment order must affect canonical form because " +
			"REVOKE-after-GRANT and GRANT-after-REVOKE produce different end states")
	}
}

func TestCanonicalPerms_SQLWhitespaceNormalised(t *testing.T) {
	a := &auth.DBPermissions{
		SQL: []string{"GRANT  SELECT\tON public.foo   TO {{.Role}}"},
	}
	b := &auth.DBPermissions{
		SQL: []string{"GRANT SELECT ON public.foo TO {{.Role}}"},
	}
	if canonicalPerms(a) != canonicalPerms(b) {
		t.Fatalf("whitespace differences should normalise away:\n  a=%s\n  b=%s",
			canonicalPerms(a), canonicalPerms(b))
	}
}

func TestCanonicalPerms_DefaultSchemaIsPublic(t *testing.T) {
	a := &auth.DBPermissions{Permissions: []string{"readonly"}}
	b := &auth.DBPermissions{Permissions: []string{"readonly"}, Schemas: []string{"public"}}
	if canonicalPerms(a) != canonicalPerms(b) {
		t.Fatalf("omitted Schemas should equal explicit [public]:\n  a=%s\n  b=%s",
			canonicalPerms(a), canonicalPerms(b))
	}
}

func TestCompositeGroupHash_Stable(t *testing.T) {
	p := &auth.DBPermissions{
		Permissions: []string{"readwrite"},
		Schemas:     []string{"public"},
		SQL:         []string{"GRANT SELECT ON public.audit TO {{.Role}}"},
	}
	h1 := compositeGroupHash(p)
	h2 := compositeGroupHash(p)
	if h1 != h2 || len(h1) != 16 {
		t.Fatalf("hash should be deterministic and 16 hex chars: h1=%q h2=%q", h1, h2)
	}
}

func TestCompositeGroupHash_DiffersOnChange(t *testing.T) {
	a := &auth.DBPermissions{
		Permissions: []string{"readonly"},
		Schemas:     []string{"public"},
		SQL:         []string{"GRANT SELECT ON public.foo TO {{.Role}}"},
	}
	b := &auth.DBPermissions{
		Permissions: []string{"readonly"},
		Schemas:     []string{"public"},
		SQL:         []string{"GRANT SELECT ON public.bar TO {{.Role}}"},
	}
	if compositeGroupHash(a) == compositeGroupHash(b) {
		t.Fatal("different SQL fragments must produce different hashes")
	}
}

func TestDesiredGroups_PurePresetPath(t *testing.T) {
	perms := &auth.DBPermissions{
		Permissions: []string{"readonly", "readwrite"},
		Schemas:     []string{"public", "audit"},
	}
	got := desiredGroups(perms, "redo")
	want := map[string]bool{
		"wp_grp_readonly_public_redo":  true,
		"wp_grp_readonly_audit_redo":   true,
		"wp_grp_readwrite_public_redo": true,
		"wp_grp_readwrite_audit_redo":  true,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d groups, got %d: %v", len(want), len(got), got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected group %q in result", g)
		}
	}
}

func TestDesiredGroups_CompositePathOnSQL(t *testing.T) {
	perms := &auth.DBPermissions{
		Permissions: []string{"readonly"},
		Schemas:     []string{"public"},
		SQL:         []string{"GRANT SELECT ON public.foo TO {{.Role}}"},
	}
	got := desiredGroups(perms, "redo")
	if len(got) != 1 {
		t.Fatalf("expected 1 composite group, got %v", got)
	}
	if !strings.HasPrefix(got[0], "wp_grp_perms_") {
		t.Errorf("composite group name should start with wp_grp_perms_, got %q", got[0])
	}
	if !strings.HasSuffix(got[0], "_redo") {
		t.Errorf("composite group name should end with _redo, got %q", got[0])
	}
}

func TestDesiredGroups_NilOrEmpty(t *testing.T) {
	if g := desiredGroups(nil, "redo"); g != nil {
		t.Errorf("nil perms should yield no groups, got %v", g)
	}
	if g := desiredGroups(&auth.DBPermissions{}, "redo"); g != nil {
		t.Errorf("empty perms should yield no groups, got %v", g)
	}
}

func TestPresetGroupName_FitsIdentifierLimit(t *testing.T) {
	name := presetGroupName("readwrite", "public", "redo")
	if len(name) > 63 {
		t.Fatalf("preset group name exceeds 63 chars: %q (%d)", name, len(name))
	}
	if name != "wp_grp_readwrite_public_redo" {
		t.Fatalf("got %q", name)
	}
}

func TestCompositeGroupName_FitsIdentifierLimit(t *testing.T) {
	p := &auth.DBPermissions{SQL: []string{"GRANT SELECT ON public.x TO {{.Role}}"}}
	name := compositeGroupName(p, strings.Repeat("d", 30))
	if len(name) > 63 {
		t.Fatalf("composite group name exceeds 63 chars: %q (%d)", name, len(name))
	}
}

func TestUsesCompositePath(t *testing.T) {
	if usesCompositePath(nil) {
		t.Error("nil perms should not use composite path")
	}
	if usesCompositePath(&auth.DBPermissions{Permissions: []string{"readonly"}}) {
		t.Error("preset-only perms should not use composite path")
	}
	if !usesCompositePath(&auth.DBPermissions{SQL: []string{"GRANT SELECT ON x TO {{.Role}}"}}) {
		t.Error("any SQL fragment forces composite path")
	}
}

func TestBuildDefaultPrivilegeStatements_NoCreators(t *testing.T) {
	if stmts := buildDefaultPrivilegeStatements(nil, "readonly", "public", "wp_grp_readonly_public_db"); stmts != nil {
		t.Errorf("expected no statements without creator roles, got %v", stmts)
	}
}

func TestBuildDefaultPrivilegeStatements_UnknownPreset(t *testing.T) {
	if stmts := buildDefaultPrivilegeStatements([]string{"migrator"}, "bogus", "public", "grp"); stmts != nil {
		t.Errorf("expected no statements for unknown preset, got %v", stmts)
	}
}

func TestBuildDefaultPrivilegeStatements_Readonly(t *testing.T) {
	stmts := buildDefaultPrivilegeStatements([]string{"migrator"}, "readonly", "public", "wp_grp_readonly_public_db")
	want := []string{
		`ALTER DEFAULT PRIVILEGES FOR ROLE "migrator" IN SCHEMA "public" GRANT SELECT ON TABLES TO "wp_grp_readonly_public_db"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "migrator" IN SCHEMA "public" GRANT SELECT ON SEQUENCES TO "wp_grp_readonly_public_db"`,
	}
	if len(stmts) != len(want) {
		t.Fatalf("expected %d statements, got %d: %v", len(want), len(stmts), stmts)
	}
	for i, s := range stmts {
		if s != want[i] {
			t.Errorf("stmt[%d] = %q, want %q", i, s, want[i])
		}
	}
}

func TestBuildDefaultPrivilegeStatements_ReadwriteMirrorsWrites(t *testing.T) {
	stmts := buildDefaultPrivilegeStatements([]string{"migrator"}, "readwrite", "public", "grp")
	joined := strings.Join(stmts, "\n")
	for _, frag := range []string{"INSERT", "UPDATE", "DELETE", "USAGE, SELECT ON SEQUENCES"} {
		if !strings.Contains(joined, frag) {
			t.Errorf("readwrite default privileges should include %q: %v", frag, stmts)
		}
	}
}

func TestBuildDefaultPrivilegeStatements_MultipleCreators(t *testing.T) {
	stmts := buildDefaultPrivilegeStatements([]string{"a", "b"}, "admin", "public", "grp")
	// admin has 2 grant clauses (tables, sequences) × 2 creators = 4.
	if len(stmts) != 4 {
		t.Fatalf("expected 4 statements, got %d: %v", len(stmts), stmts)
	}
	if !strings.Contains(stmts[0], `FOR ROLE "a"`) || !strings.Contains(stmts[len(stmts)-1], `FOR ROLE "b"`) {
		t.Errorf("expected per-creator statements, got %v", stmts)
	}
}

func TestBuildDefaultPrivilegeStatements_SanitizesIdentifiers(t *testing.T) {
	// A creator role with a double-quote must be escaped, not interpolated raw.
	stmts := buildDefaultPrivilegeStatements([]string{`ev"il`}, "readonly", "public", "grp")
	if len(stmts) == 0 {
		t.Fatal("expected statements")
	}
	if !strings.Contains(stmts[0], `"ev""il"`) {
		t.Errorf("creator identifier not safely quoted: %q", stmts[0])
	}
}
