package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/redoapp/waypoint/internal/auth"
)

// groupReadyTTL bounds how long Redis trusts that a group role's
// bootstrap is still in place. A cache miss is harmless because
// bootstrap is idempotent.
const groupReadyTTL = 24 * time.Hour

// presetGroupName returns the shared group role name for a (preset,
// schema, database) tuple. Every user requesting that combination
// becomes a member of the same group, so the expensive object-level
// GRANTs happen once per group instead of per user.
func presetGroupName(preset, schema, database string) string {
	return clampIdentifier("wp_grp_" + sanitize(preset) + "_" + sanitize(schema) + "_" + sanitize(database))
}

// compositeGroupName returns the content-addressed group role name for
// an arbitrary permission set whose raw SQL fragments mean we can't
// safely share preset groups. The name is deterministic for any
// permission set that canonicalises identically; any change in
// presets, schemas, or SQL fragments produces a fresh group.
func compositeGroupName(perms *auth.DBPermissions, database string) string {
	return clampIdentifier("wp_grp_perms_" + compositeGroupHash(perms) + "_" + sanitize(database))
}

// compositeGroupHash hashes the canonical encoding of a permission set
// to 16 hex chars (8 bytes of sha256). Collision risk at this size is
// negligible for the population of perm sets a waypoint deployment
// ever sees.
func compositeGroupHash(perms *auth.DBPermissions) string {
	sum := sha256.Sum256([]byte(canonicalPerms(perms)))
	return hex.EncodeToString(sum[:8])
}

// canonicalPerms returns the stable serialisation used as the
// composite hash input. Presets and schemas are sorted because they
// are unordered sets. SQL fragments are kept in declared order with
// whitespace collapsed, because REVOKE / ALTER DEFAULT statements
// cancel earlier GRANTs in the same list only when applied in that
// order.
func canonicalPerms(perms *auth.DBPermissions) string {
	type canonical struct {
		Permissions []string `json:"permissions"`
		Schemas     []string `json:"schemas"`
		SQL         []string `json:"sql"`
	}
	c := canonical{}
	if perms != nil {
		c.Permissions = append(c.Permissions, perms.Permissions...)
		sort.Strings(c.Permissions)
		if len(perms.Schemas) == 0 {
			c.Schemas = []string{"public"}
		} else {
			c.Schemas = append(c.Schemas, perms.Schemas...)
			sort.Strings(c.Schemas)
		}
		for _, s := range perms.SQL {
			c.SQL = append(c.SQL, normalizeWhitespace(s))
		}
	}
	if c.Permissions == nil {
		c.Permissions = []string{}
	}
	if c.Schemas == nil {
		c.Schemas = []string{"public"}
	}
	if c.SQL == nil {
		c.SQL = []string{}
	}
	b, _ := json.Marshal(c)
	return string(b)
}

var whitespaceRE = regexp.MustCompile(`\s+`)

func normalizeWhitespace(s string) string {
	return strings.TrimSpace(whitespaceRE.ReplaceAllString(s, " "))
}

// clampIdentifier truncates an identifier to PG's 63-byte limit,
// appending a short hash suffix to keep names unique if they'd
// otherwise collide after truncation.
func clampIdentifier(name string) string {
	if len(name) <= 63 {
		return name
	}
	h := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(h[:4])
	return name[:63-9] + "_" + suffix
}

// usesCompositePath reports whether a permission set requires the
// content-addressed composite group (vs. shared preset groups). Raw
// SQL fragments force the composite path so REVOKE / ALTER DEFAULT
// statements act as deltas on the preset-derived GRANTs in the same
// group, preserving the author's intent.
func usesCompositePath(perms *auth.DBPermissions) bool {
	return perms != nil && len(perms.SQL) > 0
}

// desiredGroups returns the set of group role names that the given
// permission set requires the user to be a member of.
func desiredGroups(perms *auth.DBPermissions, database string) []string {
	if perms == nil {
		return nil
	}
	if usesCompositePath(perms) {
		return []string{compositeGroupName(perms, database)}
	}
	if len(perms.Permissions) == 0 {
		return nil
	}
	schemas := perms.Schemas
	if len(schemas) == 0 {
		schemas = []string{"public"}
	}
	seen := make(map[string]struct{})
	var groups []string
	for _, preset := range perms.Permissions {
		for _, schema := range schemas {
			name := presetGroupName(preset, schema, database)
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			groups = append(groups, name)
		}
	}
	sort.Strings(groups)
	return groups
}

// ensurePresetGroup creates the shared (preset, schema, database) group
// role if it doesn't already exist, and applies the preset's GRANT
// fragments to it. Idempotent — when Redis says the group is ready we
// skip the whole thing; on a miss we re-issue the GRANTs (CockroachDB
// and Postgres both treat repeated GRANT as a no-op).
func (p *Provisioner) ensurePresetGroup(ctx context.Context, tx pgx.Tx, dialect Dialect, preset, schema, database string) (string, error) {
	name := presetGroupName(preset, schema, database)
	if ok, _ := p.store.IsGroupReady(ctx, name); ok {
		return name, nil
	}
	if err := createGroupRoleIfMissing(ctx, tx, dialect, name); err != nil {
		return "", err
	}
	fragments, err := ExpandPresets([]string{preset}, []string{schema})
	if err != nil {
		return "", fmt.Errorf("expand preset %q: %w", preset, err)
	}
	quoted := pgx.Identifier{name}.Sanitize()
	for _, frag := range fragments {
		if _, err := tx.Exec(ctx, fmt.Sprintf("GRANT %s TO %s", frag, quoted)); err != nil {
			return "", fmt.Errorf("grant %q to group: %w", frag, err)
		}
	}
	if err := p.applyDefaultPrivileges(ctx, tx, preset, schema, name); err != nil {
		return "", err
	}
	_ = p.store.MarkGroupReady(ctx, name, groupReadyTTL)
	return name, nil
}

// applyDefaultPrivileges installs ALTER DEFAULT PRIVILEGES entries so that
// tables and sequences created in the future by one of the configured
// table-creator roles automatically carry this preset group's privileges.
// GRANT ... ON ALL TABLES only affects objects that exist at grant time, so
// without this, tables created after a group is bootstrapped stay invisible
// to its members until the next re-bootstrap. This runs only for preset
// groups — the composite/raw-SQL path lets authors manage their own
// ALTER DEFAULT PRIVILEGES explicitly — and only when creator roles are
// configured.
func (p *Provisioner) applyDefaultPrivileges(ctx context.Context, tx pgx.Tx, preset, schema, group string) error {
	for _, stmt := range buildDefaultPrivilegeStatements(p.tableCreatorRoles, preset, schema, group) {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("apply default privileges (%s, schema %q): %w", preset, schema, err)
		}
	}
	return nil
}

// buildDefaultPrivilegeStatements returns the ALTER DEFAULT PRIVILEGES
// statements that mirror a preset's table/sequence grants onto future
// objects created by each creator role. It returns nil when there are no
// creator roles or the preset has no default-privilege analogue.
func buildDefaultPrivilegeStatements(creators []string, preset, schema, group string) []string {
	grants := defaultPrivilegeGrants(preset)
	if len(creators) == 0 || len(grants) == 0 {
		return nil
	}
	quotedGroup := pgx.Identifier{group}.Sanitize()
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	var stmts []string
	for _, creator := range creators {
		quotedCreator := pgx.Identifier{creator}.Sanitize()
		for _, grant := range grants {
			stmts = append(stmts, fmt.Sprintf(
				"ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT %s TO %s",
				quotedCreator, quotedSchema, grant, quotedGroup,
			))
		}
	}
	return stmts
}

// ensureCompositeGroup creates the content-addressed composite group
// for a permission set with raw SQL fragments and applies both the
// preset-derived GRANTs and the raw fragments to it. The {{.Role}}
// template inside fragments resolves to the group's own identifier so
// REVOKE / ALTER DEFAULT statements act as deltas on top of the
// preset GRANTs at group-create time, preserving the author's intent.
func (p *Provisioner) ensureCompositeGroup(ctx context.Context, tx pgx.Tx, dialect Dialect, perms *auth.DBPermissions, database string) (string, error) {
	name := compositeGroupName(perms, database)
	if ok, _ := p.store.IsGroupReady(ctx, name); ok {
		return name, nil
	}
	if err := createGroupRoleIfMissing(ctx, tx, dialect, name); err != nil {
		return "", err
	}
	quoted := pgx.Identifier{name}.Sanitize()

	if len(perms.Permissions) > 0 {
		schemas := perms.Schemas
		if len(schemas) == 0 {
			schemas = []string{"public"}
		}
		fragments, err := ExpandPresets(perms.Permissions, schemas)
		if err != nil {
			return "", fmt.Errorf("expand presets: %w", err)
		}
		for _, frag := range fragments {
			if _, err := tx.Exec(ctx, fmt.Sprintf("GRANT %s TO %s", frag, quoted)); err != nil {
				return "", fmt.Errorf("grant %q to composite group: %w", frag, err)
			}
		}
	}

	if len(perms.SQL) > 0 {
		if !p.allowRawSQL {
			return "", fmt.Errorf("raw SQL statements are disabled by server configuration; use presets instead")
		}
		if err := validateSQL(perms.SQL); err != nil {
			return "", fmt.Errorf("invalid sql in permissions: %w", err)
		}
		for _, raw := range perms.SQL {
			resolved, err := renderSQL(raw, SQLTemplateData{Role: quoted})
			if err != nil {
				return "", fmt.Errorf("invalid sql template %q: %w", raw, err)
			}
			if _, err := tx.Exec(ctx, resolved); err != nil {
				return "", fmt.Errorf("sql statement %q: %w", raw, err)
			}
		}
	}

	_ = p.store.MarkGroupReady(ctx, name, groupReadyTTL)
	return name, nil
}

// createGroupRoleIfMissing creates a NOLOGIN role if it doesn't yet
// exist. CockroachDB's CREATE ROLE syntax doesn't support IF NOT
// EXISTS uniformly across versions, so check first.
func createGroupRoleIfMissing(ctx context.Context, tx pgx.Tx, dialect Dialect, name string) error {
	var exists bool
	if err := tx.QueryRow(ctx, roleExistsQuery(dialect), name).Scan(&exists); err != nil {
		return fmt.Errorf("check group role %q: %w", name, err)
	}
	if exists {
		return nil
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf("CREATE ROLE %s NOLOGIN", pgx.Identifier{name}.Sanitize())); err != nil {
		return fmt.Errorf("create group role %q: %w", name, err)
	}
	return nil
}

// currentGroupMemberships returns the waypoint-managed group roles
// `user` is currently a direct member of. We filter on the wp_grp_
// prefix so we never accidentally REVOKE operator-managed
// memberships out from under a user.
func currentGroupMemberships(ctx context.Context, tx pgx.Tx, user string) ([]string, error) {
	rows, err := tx.Query(ctx, `
SELECT r.rolname
FROM pg_catalog.pg_auth_members m
JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
JOIN pg_catalog.pg_roles u ON u.oid = m.member
WHERE u.rolname = $1`, user)
	if err != nil {
		return nil, fmt.Errorf("query memberships: %w", err)
	}
	defer rows.Close()
	var groups []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan membership: %w", err)
		}
		if strings.HasPrefix(name, "wp_grp_") {
			groups = append(groups, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read memberships: %w", err)
	}
	sort.Strings(groups)
	return groups, nil
}
