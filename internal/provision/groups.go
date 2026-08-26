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
// Group naming.
//
// A group role is owned by the admin that created it, and Postgres 16 grants
// ADMIN OPTION only to that creator — so a second admin cannot grant a group
// the first one made. Group names therefore carry the same prefix and listener
// the user roles do: each provisioner owns its own groups, and two listeners
// over one backend with different non-superuser admins no longer collide.
//
// This also makes user_prefix mean something for groups. It previously did
// not: a deployment with user_prefix = "acme_" got roles named acme_* and
// groups named wp_grp_*, which the cleanup docs describe as sharing a prefix.
func (p *Provisioner) groupPrefix() string {
	prefix := p.userPrefix
	if prefix == "" {
		prefix = "wp_"
	}
	prefix += "grp_"
	if listener := sanitize(p.listener); listener != "" {
		prefix += listener + "_"
	}
	return prefix
}

func (p *Provisioner) presetGroupName(preset, schema, database string) string {
	return p.clampIdentifier(p.groupPrefix() + sanitize(preset) + "_" + sanitize(schema) + "_" + sanitize(database))
}

// compositeGroupName returns the content-addressed group role name for
// an arbitrary permission set whose raw SQL fragments mean we can't
// safely share preset groups. The name is deterministic for any
// permission set that canonicalises identically; any change in
// presets, schemas, or SQL fragments produces a fresh group.
func (p *Provisioner) compositeGroupName(perms *auth.DBPermissions, database string) string {
	return p.clampIdentifier(p.groupPrefix() + "perms_" + compositeGroupHash(perms) + "_" + sanitize(database))
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
// clampIdentifier bounds a group name using the same scheme as role names, so
// there is one truncation rule to reason about, and logs it for the same
// reason: a truncated identifier has to be traceable back to what produced it.
func (p *Provisioner) clampIdentifier(name string) string {
	truncated := truncateWithHash(name, maxPGIdentifier)
	if truncated != name {
		p.truncations.record(p.logger, "group", name, truncated, maxPGIdentifier)
	}
	return truncated
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
func (p *Provisioner) desiredGroups(perms *auth.DBPermissions, database string) []string {
	if perms == nil {
		return nil
	}
	if usesCompositePath(perms) {
		return []string{p.compositeGroupName(perms, database)}
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
			name := p.presetGroupName(preset, schema, database)
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
	name := p.presetGroupName(preset, schema, database)
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
	_ = p.store.MarkGroupReady(ctx, name, groupReadyTTL)
	return name, nil
}

// ensureCompositeGroup creates the content-addressed composite group
// for a permission set with raw SQL fragments and applies both the
// preset-derived GRANTs and the raw fragments to it. The {{.Role}}
// template inside fragments resolves to the group's own identifier so
// REVOKE / ALTER DEFAULT statements act as deltas on top of the
// preset GRANTs at group-create time, preserving the author's intent.
func (p *Provisioner) ensureCompositeGroup(ctx context.Context, tx pgx.Tx, dialect Dialect, perms *auth.DBPermissions, database string) (string, error) {
	name := p.compositeGroupName(perms, database)
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
// `user` is currently a direct member of. We filter on this provisioner's
// group prefix so we never accidentally REVOKE operator-managed memberships —
// or another listener's groups — out from under a user.
func (p *Provisioner) currentGroupMemberships(ctx context.Context, tx pgx.Tx, user string) ([]string, error) {
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
		if strings.HasPrefix(name, p.groupPrefix()) {
			groups = append(groups, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read memberships: %w", err)
	}
	sort.Strings(groups)
	return groups, nil
}
