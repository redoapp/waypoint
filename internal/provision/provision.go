package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/restrict"
)

// Provisioner manages dynamic PostgreSQL user lifecycle.
type Provisioner struct {
	adminConnStr string
	userPrefix   string
	allowRawSQL  bool
	peerService  string
	store        *restrict.RedisStore
	logger       *slog.Logger
	dialFunc     func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupFunc   func(ctx context.Context, host string) ([]string, error)
}

// NewProvisioner creates a new Provisioner.
func NewProvisioner(adminUser, adminPassword, adminDatabase, backend, userPrefix string, backendTLS, allowRawSQL bool, peerService string, store *restrict.RedisStore, logger *slog.Logger, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error), lookupFunc func(ctx context.Context, host string) ([]string, error)) *Provisioner {
	sslmode := "disable"
	if backendTLS {
		sslmode = "require"
	}
	connStr := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(adminUser, adminPassword),
		Host:     backend,
		Path:     "/" + adminDatabase,
		RawQuery: "sslmode=" + sslmode,
	}).String()
	if userPrefix == "" {
		userPrefix = "wp_"
	}
	return &Provisioner{
		adminConnStr: connStr,
		userPrefix:   userPrefix,
		allowRawSQL:  allowRawSQL,
		peerService:  peerService,
		store:        store,
		logger:       logger,
		dialFunc:     dialFunc,
		lookupFunc:   lookupFunc,
	}
}

// EnsureUser creates or updates a dynamic PG role for the given identity,
// node, and database. Returns the PG username and password.
func (p *Provisioner) EnsureUser(ctx context.Context, loginName, nodeName, database string, perms *auth.DBPermissions) (string, string, error) {
	tracer := otel.Tracer("waypoint")
	ctx, span := tracer.Start(ctx, "waypoint.provision.ensure_user",
		trace.WithAttributes(
			attribute.String("waypoint.user", loginName),
			attribute.String("waypoint.database", database),
		),
	)
	defer span.End()

	pgUser := p.formatUsername(loginName, nodeName, database)
	p.logger.Debug("ensuring user", "login", loginName, "database", database)

	// Acquire a distributed lock via Redis to serialize concurrent EnsureUser
	// calls for the same role. This works with both PostgreSQL and CockroachDB.
	const lockTTL = 30 * time.Second
	const maxRetries = 10
	const retryDelay = 100 * time.Millisecond

	ctx, lockSpan := tracer.Start(ctx, "waypoint.provision.acquire_lock")
	var lockToken string
	for i := 0; i < maxRetries; i++ {
		token, err := p.store.AcquireLock(ctx, "role:"+pgUser, lockTTL)
		if err != nil {
			lockSpan.RecordError(err)
			lockSpan.SetStatus(codes.Error, "acquire lock failed")
			lockSpan.End()
			span.RecordError(err)
			return "", "", fmt.Errorf("acquire lock: %w", err)
		}
		if token != "" {
			lockToken = token
			break
		}
		select {
		case <-ctx.Done():
			lockSpan.End()
			return "", "", ctx.Err()
		case <-time.After(retryDelay):
		}
	}
	if lockToken == "" {
		err := fmt.Errorf("could not acquire lock for role %q", pgUser)
		lockSpan.RecordError(err)
		lockSpan.SetStatus(codes.Error, "lock timeout")
		lockSpan.End()
		span.RecordError(err)
		return "", "", err
	}
	lockSpan.End()
	defer p.store.ReleaseLock(ctx, "role:"+pgUser, lockToken)
	p.logger.Debug("acquired lock", "role", pgUser)

	connCfg, err := pgx.ParseConfig(p.adminConnStr)
	if err != nil {
		span.RecordError(err)
		return "", "", fmt.Errorf("parse admin conn config: %w", err)
	}
	if p.dialFunc != nil {
		connCfg.DialFunc = p.dialFunc
	}
	if p.lookupFunc != nil {
		connCfg.LookupFunc = p.lookupFunc
	}

	tracerOpts := []otelpgx.Option{
		otelpgx.WithTrimSQLInSpanName(),
	}
	if p.peerService != "" {
		tracerOpts = append(tracerOpts, otelpgx.WithTracerAttributes(
			attribute.String("peer.service", p.peerService),
		))
	}
	connCfg.Tracer = otelpgx.NewTracer(tracerOpts...)

	// Bound the entire provisioning DB interaction (DNS + connect + SQL).
	const provisionTimeout = 90 * time.Second
	connCtx, connCancel := context.WithTimeout(ctx, provisionTimeout)
	defer connCancel()

	p.logger.Debug("connecting to admin db", "host", connCfg.Host, "database", connCfg.Database)
	ctx, connectSpan := tracer.Start(ctx, "waypoint.provision.connect")
	conn, err := pgx.ConnectConfig(connCtx, connCfg)
	if err != nil {
		connectSpan.RecordError(err)
		connectSpan.SetStatus(codes.Error, "connect failed")
		connectSpan.End()
		span.RecordError(err)
		return "", "", fmt.Errorf("admin connect: %w", err)
	}
	connectSpan.End()
	defer conn.Close(ctx)
	p.logger.Debug("connected to admin db")

	// Detect database dialect (PostgreSQL vs CockroachDB).
	dialect := detectDialect(ctx, conn, p.adminConnStr)
	p.logger.Debug("detected dialect", "dialect", dialect)

	// Check if user exists.
	var exists bool
	err = conn.QueryRow(ctx, roleExistsQuery(dialect), pgUser).Scan(&exists)
	if err != nil {
		span.RecordError(err)
		return "", "", fmt.Errorf("check role: %w", err)
	}

	password := generatePassword()

	_, roleSpan := tracer.Start(ctx, "waypoint.provision.create_role",
		trace.WithAttributes(attribute.Bool("waypoint.role_exists", exists)),
	)
	if !exists {
		// CREATE ROLE with LOGIN.
		// Note: role names and passwords can't be parameterized, using QuoteIdentifier.
		_, err = conn.Exec(ctx, fmt.Sprintf(
			"CREATE ROLE %s WITH LOGIN PASSWORD %s",
			pgx.Identifier{pgUser}.Sanitize(),
			quoteLiteral(password),
		))
		if err != nil {
			roleSpan.RecordError(err)
			roleSpan.SetStatus(codes.Error, "create role failed")
			roleSpan.End()
			span.RecordError(err)
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
			roleSpan.RecordError(err)
			roleSpan.SetStatus(codes.Error, "alter role failed")
			roleSpan.End()
			span.RecordError(err)
			return "", "", fmt.Errorf("alter role password: %w", err)
		}
	}
	roleSpan.End()

	// Reconcile grants: GRANT CONNECT on the database, then apply permissions.
	_, grantSpan := tracer.Start(ctx, "waypoint.provision.grant")
	_, err = conn.Exec(ctx, fmt.Sprintf(
		"GRANT CONNECT ON DATABASE %s TO %s",
		pgx.Identifier{database}.Sanitize(),
		pgx.Identifier{pgUser}.Sanitize(),
	))
	if err != nil {
		p.logger.Warn("grant connect failed", "role", pgUser, "database", database, "error", err)
	}

	// Apply permission presets and raw SQL statements.
	if perms != nil {
		sanitizedRole := pgx.Identifier{pgUser}.Sanitize()

		// Expand preset names into GRANT fragments.
		if len(perms.Permissions) > 0 {
			fragments, err := ExpandPresets(perms.Permissions, perms.Schemas)
			if err != nil {
				grantSpan.End()
				return "", "", fmt.Errorf("invalid permissions: %w", err)
			}
			for _, frag := range fragments {
				stmt := fmt.Sprintf("GRANT %s TO %s", frag, sanitizedRole)
				if _, err := conn.Exec(ctx, stmt); err != nil {
					p.logger.Warn("grant failed", "role", pgUser, "grant", frag, "error", err)
				}
			}
		}

		// Apply raw SQL statements (if allowed by config).
		if len(perms.SQL) > 0 {
			if !p.allowRawSQL {
				grantSpan.End()
				return "", "", fmt.Errorf("raw SQL statements are disabled by server configuration; use presets instead")
			}
			if err := validateSQL(perms.SQL); err != nil {
				grantSpan.End()
				return "", "", fmt.Errorf("invalid sql in permissions: %w", err)
			}
			for _, raw := range perms.SQL {
				resolved, err := renderSQL(raw, SQLTemplateData{Role: sanitizedRole})
				if err != nil {
					grantSpan.End()
					return "", "", fmt.Errorf("invalid sql template %q: %w", raw, err)
				}
				if _, err := conn.Exec(ctx, resolved); err != nil {
					p.logger.Warn("sql statement failed", "role", pgUser, "sql", raw, "error", err)
				}
			}
		}
	}

	grantSpan.End()

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
