package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/redoapp/waypoint/internal/restrict"
)

// roleLockKey computes a stable advisory lock key from a role name using FNV-1a.
func roleLockKey(roleName string) int64 {
	h := fnv.New64a()
	h.Write([]byte(roleName))
	return int64(h.Sum64())
}

// Provisioner manages dynamic PostgreSQL user lifecycle.
type Provisioner struct {
	adminConnStr string
	userPrefix   string
	store        *restrict.RedisStore
	logger       *slog.Logger
}

// NewProvisioner creates a new Provisioner.
func NewProvisioner(adminUser, adminPassword, adminDatabase, backend, userPrefix string, store *restrict.RedisStore, logger *slog.Logger) *Provisioner {
	connStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		adminUser, adminPassword, backend, adminDatabase)
	if userPrefix == "" {
		userPrefix = "wp_"
	}
	return &Provisioner{
		adminConnStr: connStr,
		userPrefix:   userPrefix,
		store:        store,
		logger:       logger,
	}
}

// EnsureUser creates or updates a dynamic PG role for the given identity,
// node, and database. Returns the PG username and password.
func (p *Provisioner) EnsureUser(ctx context.Context, loginName, nodeName, database string, permissions []string) (string, string, error) {
	pgUser := p.formatUsername(loginName, nodeName, database)

	conn, err := pgx.Connect(ctx, p.adminConnStr)
	if err != nil {
		return "", "", fmt.Errorf("admin connect: %w", err)
	}
	defer conn.Close(ctx)

	// Acquire a session-level advisory lock keyed on the role name to serialize
	// concurrent EnsureUser calls for the same role.
	lockKey := roleLockKey(pgUser)
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
		return "", "", fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", lockKey)
	}()

	// Check if user exists.
	var exists bool
	err = conn.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", pgUser).Scan(&exists)
	if err != nil {
		return "", "", fmt.Errorf("check role: %w", err)
	}

	password := generatePassword()

	if !exists {
		// CREATE ROLE with LOGIN.
		// Note: role names and passwords can't be parameterized, using QuoteIdentifier.
		_, err = conn.Exec(ctx, fmt.Sprintf(
			"CREATE ROLE %s WITH LOGIN PASSWORD %s",
			pgx.Identifier{pgUser}.Sanitize(),
			quoteLiteral(password),
		))
		if err != nil {
			return "", "", fmt.Errorf("create role: %w", err)
		}
		p.logger.Info("created PG role", "role", pgUser)
	} else {
		// Update password on every connection.
		_, err = conn.Exec(ctx, fmt.Sprintf(
			"ALTER ROLE %s WITH PASSWORD %s",
			pgx.Identifier{pgUser}.Sanitize(),
			quoteLiteral(password),
		))
		if err != nil {
			return "", "", fmt.Errorf("alter role password: %w", err)
		}
	}

	// Reconcile grants: GRANT CONNECT on the database, then apply permissions.
	_, err = conn.Exec(ctx, fmt.Sprintf(
		"GRANT CONNECT ON DATABASE %s TO %s",
		pgx.Identifier{database}.Sanitize(),
		pgx.Identifier{pgUser}.Sanitize(),
	))
	if err != nil {
		p.logger.Warn("grant connect failed", "role", pgUser, "database", database, "error", err)
	}

	// Apply permission grants.
	for _, perm := range permissions {
		stmt := fmt.Sprintf("GRANT %s TO %s", perm, pgx.Identifier{pgUser}.Sanitize())
		if _, err := conn.Exec(ctx, stmt); err != nil {
			p.logger.Warn("grant failed", "role", pgUser, "grant", perm, "error", err)
		}
	}

	// Touch last-used timestamp.
	p.store.TouchLastUsed(ctx, pgUser)

	return pgUser, password, nil
}

// formatUsername builds: {prefix}{login_sanitized}_{node}_{database}
// Truncated to 63 chars (PG limit) with hash suffix if needed.
func (p *Provisioner) formatUsername(loginName, nodeName, database string) string {
	sanitized := sanitize(loginName)
	node := strings.Split(nodeName, ".")[0]
	node = sanitize(node)
	db := sanitize(database)

	name := fmt.Sprintf("%s%s_%s_%s", p.userPrefix, sanitized, node, db)

	if len(name) <= 63 {
		return name
	}

	// Truncate with hash suffix for uniqueness.
	hash := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(hash[:4])
	return name[:63-9] + "_" + suffix
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func generatePassword() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate password: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// quoteLiteral escapes a string for use as a PG literal.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
