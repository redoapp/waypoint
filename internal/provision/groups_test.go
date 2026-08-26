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
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	got := p.desiredGroups(perms, "redo")
	want := map[string]bool{
		"wp_grp_pg_main_readonly_public_redo":  true,
		"wp_grp_pg_main_readonly_audit_redo":   true,
		"wp_grp_pg_main_readwrite_public_redo": true,
		"wp_grp_pg_main_readwrite_audit_redo":  true,
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
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	got := p.desiredGroups(perms, "redo")
	if len(got) != 1 {
		t.Fatalf("expected 1 composite group, got %v", got)
	}
	if !strings.HasPrefix(got[0], "wp_grp_pg_main_perms_") {
		t.Errorf("composite group name should start with wp_grp_pg_main_perms_, got %q", got[0])
	}
	if !strings.HasSuffix(got[0], "_redo") {
		t.Errorf("composite group name should end with _redo, got %q", got[0])
	}
}

func TestDesiredGroups_NilOrEmpty(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	if g := p.desiredGroups(nil, "redo"); g != nil {
		t.Errorf("nil perms should yield no groups, got %v", g)
	}
	if g := p.desiredGroups(&auth.DBPermissions{}, "redo"); g != nil {
		t.Errorf("empty perms should yield no groups, got %v", g)
	}
}

func TestPresetGroupName_FitsIdentifierLimit(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	name := p.presetGroupName("readwrite", "public", "redo")
	if len(name) > 63 {
		t.Fatalf("preset group name exceeds 63 chars: %q (%d)", name, len(name))
	}
	if name != "wp_grp_pg_main_readwrite_public_redo" {
		t.Fatalf("got %q", name)
	}
}

func TestCompositeGroupName_FitsIdentifierLimit(t *testing.T) {
	perms := &auth.DBPermissions{SQL: []string{"GRANT SELECT ON public.x TO {{.Role}}"}}
	p := &Provisioner{userPrefix: "wp_", listener: "pg-main"}
	name := p.compositeGroupName(perms, strings.Repeat("d", 30))
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

func TestGroupPrefix_ScopedToPrefixAndListener(t *testing.T) {
	// A group is owned by the admin that created it, and Postgres 16 grants
	// ADMIN OPTION only to that creator. Two provisioners must therefore
	// never derive the same group name unless they are the same provisioner.
	cases := []struct {
		name string
		a, b *Provisioner
		same bool
	}{
		{
			name: "different listeners",
			a:    &Provisioner{userPrefix: "wp_", listener: "pg-main"},
			b:    &Provisioner{userPrefix: "wp_", listener: "console"},
		},
		{
			name: "different user prefixes",
			a:    &Provisioner{userPrefix: "wire_", listener: "pg-main"},
			b:    &Provisioner{userPrefix: "console_", listener: "pg-main"},
		},
		{
			name: "identical provisioners share groups",
			a:    &Provisioner{userPrefix: "wp_", listener: "pg-main"},
			b:    &Provisioner{userPrefix: "wp_", listener: "pg-main"},
			same: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			an := tc.a.presetGroupName("readonly", "public", "appdb")
			bn := tc.b.presetGroupName("readonly", "public", "appdb")
			if tc.same && an != bn {
				t.Errorf("expected the same group, got %q and %q", an, bn)
			}
			if !tc.same && an == bn {
				t.Errorf("both provisioners derived the group %q; the second admin could not grant it", an)
			}

			perms := &auth.DBPermissions{SQL: []string{"GRANT SELECT ON public.x TO {{.Role}}"}}
			ac := tc.a.compositeGroupName(perms, "appdb")
			bc := tc.b.compositeGroupName(perms, "appdb")
			if tc.same && ac != bc {
				t.Errorf("expected the same composite group, got %q and %q", ac, bc)
			}
			if !tc.same && ac == bc {
				t.Errorf("both provisioners derived the composite group %q", ac)
			}
		})
	}
}

func TestGroupPrefix_HonoursUserPrefix(t *testing.T) {
	// user_prefix previously had no effect on group names at all: roles were
	// named acme_* while their groups were named wp_grp_*.
	p := &Provisioner{userPrefix: "acme_", listener: "pg-main"}
	name := p.presetGroupName("readonly", "public", "appdb")
	if !strings.HasPrefix(name, "acme_grp_") {
		t.Errorf("group %q does not carry the configured user_prefix", name)
	}
}

func TestGroupPrefix_DefaultsWhenPrefixUnset(t *testing.T) {
	p := &Provisioner{listener: "pg-main"}
	if name := p.presetGroupName("readonly", "public", "appdb"); !strings.HasPrefix(name, "wp_grp_") {
		t.Errorf("group %q should fall back to the wp_ prefix", name)
	}
}

func TestClampIdentifier_UsesTheRoleTruncationScheme(t *testing.T) {
	p := &Provisioner{userPrefix: "wp_", listener: strings.Repeat("listener", 8)}
	name := p.presetGroupName("readwrite", strings.Repeat("schema", 6), strings.Repeat("db", 10))

	if len(name) != maxPGIdentifier {
		t.Fatalf("len = %d, want %d", len(name), maxPGIdentifier)
	}
	// Same shape as role names: 52 kept, an underscore, 10 hex characters.
	if name[52] != '_' {
		t.Errorf("separator = %q, want an underscore", string(name[52]))
	}
	if got := name[53:]; len(got) != 10 {
		t.Errorf("hash suffix = %q, want 10 characters", got)
	}
}
