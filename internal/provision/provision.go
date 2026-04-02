package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/restrict"
)

// Provisioner manages dynamic PostgreSQL user lifecycle.
type Provisioner struct {
	adminConnStr string
	userPrefix   string
	store        *restrict.RedisStore
	logger       *slog.Logger
	dialFunc     func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewProvisioner creates a new Provisioner.
func NewProvisioner(adminUser, adminPassword, adminDatabase, backend, userPrefix string, store *restrict.RedisStore, logger *slog.Logger, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *Provisioner {
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
		dialFunc:     dialFunc,
	}
}

// EnsureUser creates or updates a dynamic PG role for the given identity,
// node, and database. Returns the PG username and password.
func (p *Provisioner) EnsureUser(ctx context.Context, loginName, nodeName, database string, perms *auth.DBPermissions) (string, string, error) {
	pgUser := p.formatUsername(loginName, nodeName, database)
	p.logger.Debug("ensuring user", "login", loginName, "database", database)

	// Acquire a distributed lock via Redis to serialize concurrent EnsureUser
	// calls for the same role. This works with both PostgreSQL and CockroachDB.
	const lockTTL = 30 * time.Second
	const maxRetries = 10
	const retryDelay = 100 * time.Millisecond

	var lockToken string
	for i := 0; i < maxRetries; i++ {
		token, err := p.store.AcquireLock(ctx, "role:"+pgUser, lockTTL)
		if err != nil {
			return "", "", fmt.Errorf("acquire lock: %w", err)
		}
		if token != "" {
			lockToken = token
			break
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(retryDelay):
		}
	}
	if lockToken == "" {
		return "", "", fmt.Errorf("could not acquire lock for role %q", pgUser)
	}
	defer p.store.ReleaseLock(ctx, "role:"+pgUser, lockToken)
	p.logger.Debug("acquired lock", "role", pgUser)

	connCfg, err := pgx.ParseConfig(p.adminConnStr)
	if err != nil {
		return "", "", fmt.Errorf("parse admin conn config: %w", err)
	}
	if p.dialFunc != nil {
		connCfg.DialFunc = p.dialFunc
		// Skip pgx's default DNS lookup — the custom DialFunc (e.g. Tailscale's
		// srv.Dial) resolves hostnames internally. Without this, pgx uses Go's
		// net.Resolver which routes through MagicDNS and cannot resolve external
		// private hostnames.
		connCfg.LookupFunc = func(_ context.Context, host string) ([]string, error) {
			return []string{host}, nil
		}
	}
	conn, err := pgx.ConnectConfig(ctx, connCfg)
	if err != nil {
		return "", "", fmt.Errorf("admin connect: %w", err)
	}
	defer conn.Close(ctx)
	p.logger.Debug("connected to admin db")

	// Detect database dialect (PostgreSQL vs CockroachDB).
	dialect := detectDialect(ctx, conn, p.adminConnStr)
	p.logger.Debug("detected dialect", "dialect", dialect)

	// Check if user exists.
	var exists bool
	err = conn.QueryRow(ctx, roleExistsQuery(dialect), pgUser).Scan(&exists)
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

	// Apply permission grants and raw SQL statements.
	if perms != nil {
		sanitizedRole := pgx.Identifier{pgUser}.Sanitize()

		for _, perm := range perms.Permissions {
			stmt := fmt.Sprintf("GRANT %s TO %s", perm, sanitizedRole)
			if _, err := conn.Exec(ctx, stmt); err != nil {
				p.logger.Warn("grant failed", "role", pgUser, "grant", perm, "error", err)
			}
		}

		if err := validateSQL(perms.SQL); err != nil {
			return "", "", fmt.Errorf("invalid sql in permissions: %w", err)
		}
		for _, raw := range perms.SQL {
			resolved, err := renderSQL(raw, SQLTemplateData{Role: sanitizedRole})
			if err != nil {
				return "", "", fmt.Errorf("invalid sql template %q: %w", raw, err)
			}
			if _, err := conn.Exec(ctx, resolved); err != nil {
				p.logger.Warn("sql statement failed", "role", pgUser, "sql", raw, "error", err)
			}
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
