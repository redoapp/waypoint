package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	"golang.org/x/sync/singleflight"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/restrict"
)

// provisionBudget bounds a coalesced provisioning round: lock wait plus the
// admin DB interaction. It is applied to the detached context that outlives
// the caller which initiated the round.
const provisionBudget = 2 * time.Minute

// pgCredentialTTL is how long a provisioned role's password stays in effect
// before the next connection rotates it. It is longer than the MongoDB and
// OpenSearch equivalents because this cache lives in Redis, so every instance
// agrees on the current password; those keep theirs per-process, where a long
// window would let two replicas disagree about what the password is.
const pgCredentialTTL = 30 * time.Minute

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

	// flight coalesces concurrent provisioning of the same role within this
	// process, so a burst of simultaneous connections costs one round.
	flight singleflight.Group

	// credTTL is how long a role's password stays in effect before the next
	// connection rotates it. Zero rotates on every connection.
	credTTL time.Duration
}

// provisionedRole is the shared result of one coalesced provisioning round.
type provisionedRole struct {
	user     string
	password string
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
		credTTL:      pgCredentialTTL,
	}
}

// SetCredentialTTL overrides how long a provisioned role's password stays in
// effect before the next connection rotates it. Zero restores rotate-on-every-
// connection. Intended for tests.
func (p *Provisioner) SetCredentialTTL(d time.Duration) {
	p.credTTL = d
}

// EnsureUser creates or updates a dynamic PG role for the given identity,
// node, and database. Returns the PG username and password.
func (p *Provisioner) EnsureUser(ctx context.Context, loginName, nodeName, database string, perms *auth.DBPermissions) (string, string, error) {
	return p.ensureUser(ctx, loginName, nodeName, database, "", perms)
}

// EnsureUserWithRoleScope creates or updates a dynamic PG role with an
// additional role-name scope. The database used for grants is unchanged.
func (p *Provisioner) EnsureUserWithRoleScope(ctx context.Context, loginName, nodeName, database, roleScope string, perms *auth.DBPermissions) (string, string, error) {
	return p.ensureUser(ctx, loginName, nodeName, database, roleScope, perms)
}

func (p *Provisioner) ensureUser(ctx context.Context, loginName, nodeName, database, roleScope string, perms *auth.DBPermissions) (string, string, error) {
	tracer := otel.Tracer("waypoint")
	spanAttrs := []attribute.KeyValue{
		attribute.String("waypoint.user", loginName),
		attribute.String("waypoint.database", database),
	}
	if roleScope != "" {
		spanAttrs = append(spanAttrs, attribute.String("waypoint.role_scope", roleScope))
	}
	ctx, span := tracer.Start(ctx, "waypoint.provision.ensure_user",
		trace.WithAttributes(spanAttrs...),
	)
	defer span.End()

	pgUser := p.formatUsernameWithScope(loginName, nodeName, database, roleScope)
	p.logger.DebugContext(ctx, "ensuring user", "login", loginName, "database", database, "role_scope", roleScope)

	// A busy lock means another connection is provisioning this same role, not
	// that anything is wrong. Wait a beat and start a fresh round rather than
	// failing the connection; only give up once the client has waited longer
	// than it is worth hanging on for.
	deadline := time.Now().Add(lockTotalBudget)
	for attempt := 0; ; attempt++ {
		// Coalesce concurrent provisioning of the same role. A client opening a
		// burst of connections needs one CREATE/ALTER ROLE and one grant
		// reconcile for all of them, not one per connection. Sharing the result
		// also means every caller in the burst receives the password that is
		// actually set on the role — previously each connection rotated it out
		// from under the ones still authenticating.
		lockBudget := min(lockAttemptBudget, time.Until(deadline))
		ch := p.flight.DoChan(pgUser, func() (any, error) {
			// Detach from the initiating caller's cancellation: if that client
			// hangs up mid-round, the others waiting on this same result still
			// need a usable role.
			workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), provisionBudget)
			defer cancel()

			password, err := p.provisionRole(workCtx, pgUser, database, perms, lockBudget)
			if err != nil {
				return nil, err
			}
			return provisionedRole{user: pgUser, password: password}, nil
		})

		var res singleflight.Result
		select {
		case <-ctx.Done():
			span.RecordError(ctx.Err())
			return "", "", ctx.Err()
		case res = <-ch:
		}

		if errors.Is(res.Err, ErrLockBusy) && time.Until(deadline) > lockBusyRetryDelay {
			p.logger.DebugContext(ctx, "role lock busy, retrying",
				"role", pgUser, "attempt", attempt+1)
			select {
			case <-ctx.Done():
				span.RecordError(ctx.Err())
				return "", "", ctx.Err()
			case <-time.After(lockBusyRetryDelay):
			}
			continue
		}
		if res.Err != nil {
			span.RecordError(res.Err)
			return "", "", res.Err
		}

		role := res.Val.(provisionedRole)
		span.SetAttributes(
			attribute.Bool("waypoint.provision.coalesced", res.Shared),
			attribute.Int("waypoint.provision.lock_attempts", attempt+1),
		)
		return role.user, role.password, nil
	}
}

// provisionRole performs one provisioning round for pgUser under the Redis
// role lock, returning the password it set. Callers reach it through the
// singleflight group in ensureUser.
func (p *Provisioner) provisionRole(ctx context.Context, pgUser, database string, perms *auth.DBPermissions, lockBudget time.Duration) (string, error) {
	tracer := otel.Tracer("waypoint")

	// Serialize against other processes via Redis. This works with both
	// PostgreSQL and CockroachDB.
	ctx, lockSpan := tracer.Start(ctx, "waypoint.provision.acquire_lock")
	release, err := acquireRoleLock(ctx, p.store, "role:"+pgUser, lockBudget)
	if err != nil {
		lockSpan.RecordError(err)
		lockSpan.SetStatus(codes.Error, "acquire lock failed")
		lockSpan.End()
		return "", err
	}
	lockSpan.End()
	defer release()
	p.logger.DebugContext(ctx, "acquired lock", "role", pgUser)

	ctx, span := tracer.Start(ctx, "waypoint.provision.role",
		trace.WithAttributes(attribute.String("waypoint.pg_user", pgUser)),
	)
	defer span.End()

	connCfg, err := pgx.ParseConfig(p.adminConnStr)
	if err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("parse admin conn config: %w", err)
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

	p.logger.DebugContext(ctx, "connecting to admin db", "host", connCfg.Host, "database", connCfg.Database)
	ctx, connectSpan := tracer.Start(ctx, "waypoint.provision.connect")
	conn, err := pgx.ConnectConfig(connCtx, connCfg)
	if err != nil {
		connectSpan.RecordError(err)
		connectSpan.SetStatus(codes.Error, "connect failed")
		connectSpan.End()
		span.RecordError(err)
		return "", fmt.Errorf("admin connect: %w", err)
	}
	connectSpan.End()
	defer conn.Close(ctx)
	p.logger.DebugContext(ctx, "connected to admin db")

	// Detect database dialect (PostgreSQL vs CockroachDB).
	dialect := detectDialect(ctx, conn, p.adminConnStr)
	p.logger.DebugContext(ctx, "detected dialect", "dialect", dialect)

	tx, err := conn.Begin(ctx)
	if err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("begin transaction: %w", err)
	}
	txCommitted := false
	defer func() {
		if !txCommitted {
			_ = tx.Rollback(ctx)
		}
	}()

	// Check if user exists.
	var exists bool
	err = tx.QueryRow(ctx, roleExistsQuery(dialect), pgUser).Scan(&exists)
	if err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("check role: %w", err)
	}

	targetDatabaseExists, err := databaseExists(ctx, tx, database)
	if err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("check database: %w", err)
	}

	// Reuse the password already in effect when it is still fresh. Rotating on
	// every connection is what let one connection invalidate the credentials
	// another was still authenticating with: the role lock is released when
	// provisioning returns, but the client only uses the password afterwards.
	// We hold the role lock here, so nothing can rotate it underneath us.
	password := ""
	if exists && p.credTTL > 0 {
		cached, credErr := p.store.GetCredential(ctx, pgUser)
		if credErr != nil {
			// Not fatal — fall through and rotate.
			p.logger.DebugContext(ctx, "credential cache read failed", "role", pgUser, "error", credErr)
		}
		password = cached
	}
	rotated := password == ""
	if rotated {
		password = generatePassword()
	}

	_, roleSpan := tracer.Start(ctx, "waypoint.provision.create_role",
		trace.WithAttributes(
			attribute.Bool("waypoint.role_exists", exists),
			attribute.Bool("waypoint.password_rotated", rotated),
		),
	)
	if !exists {
		// CREATE ROLE with LOGIN.
		// Note: role names and passwords can't be parameterized, using QuoteIdentifier.
		_, err = tx.Exec(ctx, fmt.Sprintf(
			"CREATE ROLE %s WITH LOGIN PASSWORD %s",
			pgx.Identifier{pgUser}.Sanitize(),
			quoteLiteral(password),
		))
		if err != nil {
			roleSpan.RecordError(err)
			roleSpan.SetStatus(codes.Error, "create role failed")
			roleSpan.End()
			span.RecordError(err)
			return "", fmt.Errorf("create role: %w", err)
		}
		p.logger.InfoContext(ctx, "created PG role", "role", pgUser)
	} else if rotated {
		// Only write when the password actually changed; within the cache
		// window the role already has this password.
		_, err = tx.Exec(ctx, fmt.Sprintf(
			"ALTER ROLE %s WITH PASSWORD %s",
			pgx.Identifier{pgUser}.Sanitize(),
			quoteLiteral(password),
		))
		if err != nil {
			roleSpan.RecordError(err)
			roleSpan.SetStatus(codes.Error, "alter role failed")
			roleSpan.End()
			span.RecordError(err)
			return "", fmt.Errorf("alter role password: %w", err)
		}
	}
	roleSpan.End()

	_, grantSpan := tracer.Start(ctx, "waypoint.provision.grant")
	if err := p.reconcileUserGroups(ctx, tx, dialect, pgUser, database, targetDatabaseExists, perms); err != nil {
		grantSpan.End()
		span.RecordError(err)
		return "", err
	}
	grantSpan.End()

	if err := tx.Commit(ctx); err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("commit transaction: %w", err)
	}
	txCommitted = true

	if rotated && p.credTTL > 0 {
		if err := p.store.SetCredential(ctx, pgUser, password, p.credTTL); err != nil {
			// The role is provisioned and the password works; failing to cache
			// it only costs the next connection a rotation.
			p.logger.WarnContext(ctx, "credential cache write failed", "role", pgUser, "error", err)
		}
	}

	// Touch last-used timestamp.
	p.store.TouchLastUsed(ctx, pgUser)

	return password, nil
}

// ReconcileRole updates privileges for an existing backend role without
// rotating its password. It is used by active sessions during revalidation.
func (p *Provisioner) ReconcileRole(ctx context.Context, pgUser, database string, perms *auth.DBPermissions) error {
	tracer := otel.Tracer("waypoint")
	ctx, span := tracer.Start(ctx, "waypoint.provision.reconcile_role",
		trace.WithAttributes(
			attribute.String("waypoint.pg_user", pgUser),
			attribute.String("waypoint.database", database),
		),
	)
	defer span.End()

	// Every live session for a role revalidates on its own timer, so a user
	// with many open connections reconciles the same role over and over.
	// Coalesce those into one round per role+database.
	ch := p.flight.DoChan("reconcile:"+pgUser+":"+database, func() (any, error) {
		workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), provisionBudget)
		defer cancel()
		return nil, p.reconcileRole(workCtx, pgUser, database, perms)
	})

	select {
	case <-ctx.Done():
		span.RecordError(ctx.Err())
		return ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			span.RecordError(res.Err)
			return res.Err
		}
		span.SetAttributes(attribute.Bool("waypoint.provision.coalesced", res.Shared))
		return nil
	}
}

// reconcileRole performs one privilege reconciliation round under the Redis
// role lock. Callers reach it through the singleflight group in ReconcileRole.
func (p *Provisioner) reconcileRole(ctx context.Context, pgUser, database string, perms *auth.DBPermissions) error {
	tracer := otel.Tracer("waypoint")

	ctx, lockSpan := tracer.Start(ctx, "waypoint.provision.acquire_lock")
	release, err := acquireRoleLock(ctx, p.store, "role:"+pgUser, lockTotalBudget)
	if err != nil {
		lockSpan.RecordError(err)
		lockSpan.SetStatus(codes.Error, "acquire lock failed")
		lockSpan.End()
		return err
	}
	lockSpan.End()
	defer release()

	ctx, span := tracer.Start(ctx, "waypoint.provision.reconcile")
	defer span.End()

	connCfg, err := pgx.ParseConfig(p.adminConnStr)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("parse admin conn config: %w", err)
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

	const provisionTimeout = 90 * time.Second
	connCtx, connCancel := context.WithTimeout(ctx, provisionTimeout)
	defer connCancel()

	conn, err := pgx.ConnectConfig(connCtx, connCfg)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("admin connect: %w", err)
	}
	defer conn.Close(ctx)

	dialect := detectDialect(ctx, conn, p.adminConnStr)

	tx, err := conn.Begin(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("begin transaction: %w", err)
	}
	txCommitted := false
	defer func() {
		if !txCommitted {
			_ = tx.Rollback(ctx)
		}
	}()

	var exists bool
	if err := tx.QueryRow(ctx, roleExistsQuery(dialect), pgUser).Scan(&exists); err != nil {
		span.RecordError(err)
		return fmt.Errorf("check role: %w", err)
	}
	if !exists {
		err := fmt.Errorf("role %q does not exist", pgUser)
		span.RecordError(err)
		return err
	}

	targetDatabaseExists, err := databaseExists(ctx, tx, database)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("check database: %w", err)
	}

	if err := p.reconcileUserGroups(ctx, tx, dialect, pgUser, database, targetDatabaseExists, perms); err != nil {
		span.RecordError(err)
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("commit transaction: %w", err)
	}
	txCommitted = true

	p.store.TouchLastUsed(ctx, pgUser)
	return nil
}

// reconcileUserGroups ensures the user role's group memberships match
// what the permission set requires. The expensive object-level GRANTs
// live on shared group roles (bootstrapped lazily); per-user changes
// are restricted to cheap membership writes that don't lock any
// schema descriptor.
func (p *Provisioner) reconcileUserGroups(ctx context.Context, tx pgx.Tx, dialect Dialect, pgUser, database string, targetDatabaseExists bool, perms *auth.DBPermissions) error {
	sanitizedUser := pgx.Identifier{pgUser}.Sanitize()

	if perms != nil {
		if targetDatabaseExists {
			if _, err := tx.Exec(ctx, fmt.Sprintf(
				"GRANT CONNECT ON DATABASE %s TO %s",
				pgx.Identifier{database}.Sanitize(),
				sanitizedUser,
			)); err != nil {
				return fmt.Errorf("grant connect: %w", err)
			}
		} else {
			p.logger.WarnContext(ctx, "grant connect skipped because database does not exist",
				"role", pgUser,
				"database", database,
			)
		}
	}

	desired, err := p.bootstrapGroupsForPerms(ctx, tx, dialect, perms, database)
	if err != nil {
		return err
	}

	current, err := currentGroupMemberships(ctx, tx, pgUser)
	if err != nil {
		return err
	}

	desiredSet := make(map[string]struct{}, len(desired))
	for _, g := range desired {
		desiredSet[g] = struct{}{}
	}
	currentSet := make(map[string]struct{}, len(current))
	for _, g := range current {
		currentSet[g] = struct{}{}
	}

	// When any membership is being revoked the user is effectively
	// being downgraded, so reassign any objects they currently own
	// back to the admin role. Without this, ownership-derived
	// privileges (e.g. INSERT into an object the user created while
	// holding a higher preset) would survive the downgrade. REASSIGN
	// is the only descriptor-touching operation kept in the hot path
	// and runs only on actual downgrades, not on steady-state
	// reconnects.
	revoking := false
	for _, g := range current {
		if _, ok := desiredSet[g]; !ok {
			revoking = true
			break
		}
	}
	if revoking {
		if _, err := tx.Exec(ctx, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", sanitizedUser)); err != nil {
			return fmt.Errorf("reassign owned objects: %w", err)
		}
	}

	for _, g := range desired {
		if _, ok := currentSet[g]; ok {
			continue
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf("GRANT %s TO %s", pgx.Identifier{g}.Sanitize(), sanitizedUser)); err != nil {
			return fmt.Errorf("grant group %q to %q: %w", g, pgUser, err)
		}
	}
	for _, g := range current {
		if _, ok := desiredSet[g]; ok {
			continue
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf("REVOKE %s FROM %s", pgx.Identifier{g}.Sanitize(), sanitizedUser)); err != nil {
			return fmt.Errorf("revoke group %q from %q: %w", g, pgUser, err)
		}
	}
	return nil
}

// bootstrapGroupsForPerms ensures every group role the permission set
// references exists and has its preset / SQL fragments applied,
// returning the deterministic group names so the caller can diff
// against current memberships.
func (p *Provisioner) bootstrapGroupsForPerms(ctx context.Context, tx pgx.Tx, dialect Dialect, perms *auth.DBPermissions, database string) ([]string, error) {
	if perms == nil {
		return nil, nil
	}
	if usesCompositePath(perms) {
		name, err := p.ensureCompositeGroup(ctx, tx, dialect, perms, database)
		if err != nil {
			return nil, err
		}
		return []string{name}, nil
	}
	if len(perms.Permissions) == 0 {
		return nil, nil
	}
	schemas := perms.Schemas
	if len(schemas) == 0 {
		schemas = []string{"public"}
	}
	seen := make(map[string]struct{})
	var names []string
	for _, preset := range perms.Permissions {
		for _, schema := range schemas {
			name, err := p.ensurePresetGroup(ctx, tx, dialect, preset, schema, database)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names, nil
}

func databaseExists(ctx context.Context, tx pgx.Tx, database string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", database).Scan(&exists)
	return exists, err
}

// formatUsername builds: {prefix}{login_sanitized}_{node}_{database}
// Truncated to 63 chars (PG limit) with hash suffix if needed.
func (p *Provisioner) formatUsername(loginName, nodeName, database string) string {
	return p.formatUsernameWithScope(loginName, nodeName, database, "")
}

// formatUsernameWithScope builds:
// {prefix}{login_sanitized}_{node}_{database}_{scope}
// The scope is optional and keeps intentionally different grant sets isolated.
func (p *Provisioner) formatUsernameWithScope(loginName, nodeName, database, roleScope string) string {
	sanitized := sanitize(loginName)
	node := strings.Split(nodeName, ".")[0]
	node = sanitize(node)
	db := sanitize(database)
	scope := sanitize(roleScope)

	name := fmt.Sprintf("%s%s_%s_%s", p.userPrefix, sanitized, node, db)
	if scope != "" {
		name += "_" + scope
	}

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
