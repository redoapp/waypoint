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
	"sync"
	"time"
	"unicode/utf8"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	adminConnStr  string
	adminDatabase string
	listener      string
	truncations   truncationLog
	userPrefix    string
	allowRawSQL   bool
	peerService   string
	store         *restrict.RedisStore
	logger        *slog.Logger
	dialFunc      func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupFunc    func(ctx context.Context, host string) ([]string, error)

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
//
// listener is the name of the listener this provisioner serves. It becomes
// part of every role name, so two listeners over the same backend never share
// a role even when they share a user prefix — which matters because their
// capability grants can differ, and a shared role would mean whichever
// provisioned last set the privileges for both.
func NewProvisioner(adminUser, adminPassword, adminDatabase, backend, listener, userPrefix string, backendTLS, allowRawSQL bool, peerService string, store *restrict.RedisStore, logger *slog.Logger, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error), lookupFunc func(ctx context.Context, host string) ([]string, error)) *Provisioner {
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
		adminConnStr:  connStr,
		adminDatabase: adminDatabase,
		listener:      listener,
		userPrefix:    userPrefix,
		allowRawSQL:   allowRawSQL,
		peerService:   peerService,
		store:         store,
		logger:        logger,
		dialFunc:      dialFunc,
		lookupFunc:    lookupFunc,
		credTTL:       pgCredentialTTL,
	}
}

// SetCredentialTTL overrides how long a provisioned role's password stays in
// effect before the next connection rotates it. Zero restores rotate-on-every-
// connection. Intended for tests.
func (p *Provisioner) SetCredentialTTL(d time.Duration) {
	p.credTTL = d
}

// connectTo opens an admin connection to a specific database.
//
// Which database matters. Role creation, membership grants and GRANT CONNECT
// all act on shared catalogs and work from anywhere, but privileges on
// schemas, tables and sequences are stored per database — as is REASSIGN
// OWNED. Running those over a connection to admin_database silently applied
// them to the wrong database, leaving the role with no usable privileges in
// the one it was provisioned for.
//
// Connecting to the target database instead keeps the whole operation in a
// single transaction and puts every statement where it belongs.
func (p *Provisioner) connectTo(ctx context.Context, database string) (*pgx.Conn, string, error) {
	if database == "" {
		database = p.adminDatabase
	}

	connCfg, err := pgx.ParseConfig(p.adminConnStr)
	if err != nil {
		return nil, "", fmt.Errorf("parse admin conn config: %w", err)
	}
	connCfg.Database = database
	if p.dialFunc != nil {
		connCfg.DialFunc = p.dialFunc
	}
	if p.lookupFunc != nil {
		connCfg.LookupFunc = p.lookupFunc
	}

	tracerOpts := []otelpgx.Option{otelpgx.WithTrimSQLInSpanName()}
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

	conn, err := pgx.ConnectConfig(connCtx, connCfg)
	if err != nil {
		return nil, database, err
	}
	return conn, database, nil
}

// connectToTarget opens a connection to the database being provisioned for,
// falling back to admin_database when that database does not exist. The bool
// reports whether the target database was reached.
func (p *Provisioner) connectToTarget(ctx context.Context, database string) (*pgx.Conn, bool, error) {
	if database == "" || database == p.adminDatabase {
		conn, _, err := p.connectTo(ctx, database)
		if err != nil {
			return nil, false, err
		}
		return conn, database != "", nil
	}

	conn, _, err := p.connectTo(ctx, database)
	if err == nil {
		// Postgres refuses the connection outright when the database is
		// missing, but CockroachDB accepts it — even `SELECT 1` succeeds —
		// and only fails once a catalog is touched. Probe the catalog so
		// both backends reach the same conclusion here rather than failing
		// later inside the provisioning transaction.
		if probeErr := probeDatabaseExists(ctx, conn); probeErr == nil {
			return conn, true, nil
		} else if !isInvalidCatalogName(probeErr) {
			conn.Close(ctx)
			return nil, false, probeErr
		}
		conn.Close(ctx)
	} else if !isInvalidCatalogName(err) {
		return nil, false, err
	}

	// The database does not exist. Provisioning still creates the role so
	// the caller gets a clear error from the backend rather than a
	// provisioning failure, but no database-scoped grant can be applied.
	p.logger.WarnContext(ctx, "target database does not exist; provisioning without database-scoped grants",
		"database", database)
	conn, _, err = p.connectTo(ctx, p.adminDatabase)
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}

// probeDatabaseExists issues a catalog read, which is what distinguishes a
// live database from a missing one on backends that connect regardless.
func probeDatabaseExists(ctx context.Context, conn *pgx.Conn) error {
	var n int
	return conn.QueryRow(ctx, "SELECT count(*) FROM pg_database").Scan(&n)
}

// isInvalidCatalogName reports SQLSTATE 3D000, which Postgres returns when the
// requested database does not exist.
func isInvalidCatalogName(err error) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code == "3D000"
	}
	return false
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

	// Connect to the database being provisioned for, so that schema and
	// table grants land in it rather than in admin_database.
	p.logger.DebugContext(ctx, "connecting for provisioning", "database", database)
	ctx, connectSpan := tracer.Start(ctx, "waypoint.provision.connect")
	conn, targetDatabaseExists, err := p.connectToTarget(ctx, database)
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

	// Same reasoning as ensureUser: the grants this reapplies are stored per
	// database, so they have to be issued over a connection to that database.
	conn, targetDatabaseExists, err := p.connectToTarget(ctx, database)
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

// formatUsername builds: {prefix}{login_sanitized}_{node}_{database}
// Truncated to 63 chars (PG limit) with hash suffix if needed.
func (p *Provisioner) formatUsername(loginName, nodeName, database string) string {
	return p.formatUsernameWithScope(loginName, nodeName, database, "")
}

// formatUsernameWithScope builds:
// {prefix}{login_sanitized}_{node}_{database}_{scope}
// The scope is optional and keeps intentionally different grant sets isolated.
// formatUsernameWithScope derives the role name.
//
// The listener is part of the name so that two listeners over the same backend
// get distinct roles even under a shared user_prefix. Without it, their
// capability grants would fight: both would resolve to one role and whichever
// provisioned most recently would set its privileges for both.
func (p *Provisioner) formatUsernameWithScope(loginName, nodeName, database, roleScope string) string {
	sanitized := sanitize(loginName)
	node := strings.Split(nodeName, ".")[0]
	node = sanitize(node)
	db := sanitize(database)
	listener := sanitize(p.listener)
	scope := sanitize(roleScope)

	// The listener goes directly after the prefix, not at the end. Long
	// logins and hostnames push these names past the 63-byte identifier
	// limit and the tail is what gets truncated away — so a trailing
	// listener would vanish from exactly the names where telling listeners
	// apart matters. Listener names are short and operator-chosen, so
	// leading with one costs little and always survives.
	name := p.userPrefix
	if listener != "" {
		name += listener + "_"
	}
	name += fmt.Sprintf("%s_%s_%s", sanitized, node, db)
	if scope != "" {
		name += "_" + scope
	}

	truncated := truncateWithHash(name, maxPGIdentifier)
	if truncated != name {
		p.truncations.record(p.logger, "role", name, truncated, maxPGIdentifier)
	}
	return truncated
}

// Identifier limits. Postgres truncates anything longer than NAMEDATALEN-1
// silently, which would collapse distinct users onto one role, so names are
// bounded here instead.
const (
	maxPGIdentifier    = 63
	maxMongoIdentifier = 128

	// truncationHashLen is how many hex characters of the digest are kept.
	// Ten gives 40 bits, which is ample for distinguishing the handful of
	// names that share a truncated prefix.
	truncationHashLen = 10
)

// truncateWithHash bounds an identifier to limit bytes, keeping as much of the
// readable name as possible and encoding the rest in a hash suffix. The result
// is <kept>_<10 hex characters>, filling the limit exactly.
//
// Only the discarded remainder is hashed, not the whole name. That is enough
// for uniqueness: two names that survive to the same kept prefix can differ
// only in the remainder, so their digests differ; two names with different
// kept prefixes are already distinct. It also means the suffix says something
// specific — it identifies what was dropped.
//
// The kept portion may itself end in an underscore, yielding a doubled one
// before the hash. That is a legal identifier and leaving it alone keeps the
// rule simple: the name is always exactly limit bytes, cut at a fixed offset.
// truncationLog records identifier truncations, once per distinct original
// name, so a truncated identifier seen later — in pg_stat_activity, in an
// audit log, in a permissions listing — can be traced back to the name it was
// derived from. Without this the hash suffix is opaque: it identifies what was
// dropped without saying what that was.
//
// Keyed on the original rather than the result: two different originals
// collapsing onto one identifier is the collision worth seeing, so both should
// be logged rather than the second silently suppressed.
type truncationLog struct {
	seen sync.Map
}

func (t *truncationLog) record(logger *slog.Logger, kind, original, truncated string, limit int) {
	if logger == nil {
		return
	}
	if _, dup := t.seen.LoadOrStore(original, struct{}{}); dup {
		return
	}
	// truncated is kept + "_" + hash, so the readable portion is everything
	// before those trailing bytes.
	kept := truncated[:len(truncated)-truncationHashLen-1]
	logger.Info(kind+" name truncated to fit",
		"name", truncated,
		"original", original,
		"original_bytes", len(original),
		"limit", limit,
		// The hash suffix is the digest of exactly this text, so the log
		// carries everything needed to reproduce the name.
		"dropped", strings.TrimPrefix(original, kept),
	)
}

func truncateWithHash(name string, limit int) string {
	if len(name) <= limit {
		return name
	}

	// One byte of the budget goes to the separator.
	keep := limit - truncationHashLen - 1
	// user_prefix reaches this unsanitized from config, so it can in
	// principle carry multi-byte runes. Back off to a rune boundary rather
	// than slicing one in half.
	for keep > 0 && !utf8.RuneStart(name[keep]) {
		keep--
	}

	sum := sha256.Sum256([]byte(name[keep:]))
	return name[:keep] + "_" + hex.EncodeToString(sum[:])[:truncationHashLen]
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
