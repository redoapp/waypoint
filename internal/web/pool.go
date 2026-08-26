package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/provision"
)

// Connection pooling for the console.
//
// The console is stateless per request, but it must not re-provision per
// request: EnsureUser rotates the role's password on every call, so calling it
// on each keystroke-driven completion would mean an ALTER ROLE per keystroke.
//
// The split provision already offers is exactly right here:
//
//   - EnsureUser once, when a pool is created. It rotates the password, which
//     is fine for pool setup.
//   - ReconcileRole on subsequent requests. Its contract is "updates
//     privileges for an existing backend role without rotating its password",
//     which is what keeps pooled connections valid while grants stay current.
//
// A pool is a cache, not session state. Dropping one costs a round trip, never
// correctness, and any instance can rebuild it from Redis and the database.

// reconcileInterval bounds how stale a role's privileges may get when the
// user's capability grants have not visibly changed. A change in the resolved
// permissions triggers an immediate reconcile regardless.
const reconcileInterval = 30 * time.Second

type poolManager struct {
	mu    sync.Mutex
	pools map[string]*userPool

	prov        *provision.Provisioner
	backend     string
	backendTLS  bool
	peerService string
	dialFunc    func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupFunc  func(ctx context.Context, host string) ([]string, error)

	stmtTimeout time.Duration
	maxConns    int32
	idleTimeout time.Duration
	logger      *slog.Logger
}

type userPool struct {
	mu            sync.Mutex
	pool          *pgxpool.Pool
	pgUser        string
	permsHash     string
	lastReconcile time.Time
	lastUsed      time.Time
}

func newPoolManager(
	prov *provision.Provisioner,
	backend string,
	backendTLS bool,
	peerService string,
	dialFunc func(ctx context.Context, network, addr string) (net.Conn, error),
	lookupFunc func(ctx context.Context, host string) ([]string, error),
	stmtTimeout time.Duration,
	maxConns int32,
	idleTimeout time.Duration,
	logger *slog.Logger,
) *poolManager {
	return &poolManager{
		pools:       map[string]*userPool{},
		prov:        prov,
		backend:     backend,
		backendTLS:  backendTLS,
		peerService: peerService,
		dialFunc:    dialFunc,
		lookupFunc:  lookupFunc,
		stmtTimeout: stmtTimeout,
		maxConns:    maxConns,
		idleTimeout: idleTimeout,
		logger:      logger,
	}
}

func poolKey(loginName, nodeName, database string) string {
	return loginName + "\x00" + nodeName + "\x00" + database
}

// permsFingerprint gives a stable hash of the resolved permissions so a change
// in the user's capability grants forces an immediate reconcile.
func permsFingerprint(p *auth.DBPermissions) string {
	if p == nil {
		return ""
	}
	perms := append([]string(nil), p.Permissions...)
	schemas := append([]string(nil), p.Schemas...)
	sqls := append([]string(nil), p.SQL...)
	sort.Strings(perms)
	sort.Strings(schemas)
	sort.Strings(sqls)
	h := sha256.New()
	for _, group := range [][]string{perms, schemas, sqls} {
		for _, s := range group {
			h.Write([]byte(s))
			h.Write([]byte{0})
		}
		h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

// acquire returns a pool for (user, node, database), provisioning the role on
// first use and reconciling its privileges afterwards.
func (m *poolManager) acquire(ctx context.Context, loginName, nodeName, database string, perms *auth.DBPermissions) (*pgxpool.Pool, string, error) {
	key := poolKey(loginName, nodeName, database)

	m.mu.Lock()
	up, ok := m.pools[key]
	if !ok {
		up = &userPool{}
		m.pools[key] = up
	}
	m.mu.Unlock()

	up.mu.Lock()
	defer up.mu.Unlock()
	up.lastUsed = time.Now()

	fp := permsFingerprint(perms)

	if up.pool == nil {
		pgUser, password, err := m.prov.EnsureUser(ctx, loginName, nodeName, database, perms)
		if err != nil {
			return nil, "", fmt.Errorf("provision role: %w", err)
		}
		pool, err := m.build(ctx, pgUser, password, database)
		if err != nil {
			return nil, "", err
		}
		up.pool = pool
		up.pgUser = pgUser
		up.permsHash = fp
		up.lastReconcile = time.Now()
		m.logger.InfoContext(ctx, "console pool created",
			"user", loginName, "role", pgUser, "database", database)
		return pool, pgUser, nil
	}

	// Existing pool: keep privileges current without rotating the password,
	// so in-flight connections stay valid.
	if up.permsHash != fp || time.Since(up.lastReconcile) > reconcileInterval {
		if err := m.prov.ReconcileRole(ctx, up.pgUser, database, perms); err != nil {
			return nil, "", fmt.Errorf("reconcile role: %w", err)
		}
		up.permsHash = fp
		up.lastReconcile = time.Now()
	}
	return up.pool, up.pgUser, nil
}

// invalidate tears down a pool. Used when the backend rejects the pooled
// credential, which happens when another instance re-provisioned the same role
// and rotated its password.
func (m *poolManager) invalidate(loginName, nodeName, database string) {
	key := poolKey(loginName, nodeName, database)
	m.mu.Lock()
	up, ok := m.pools[key]
	if ok {
		delete(m.pools, key)
	}
	m.mu.Unlock()
	if !ok {
		return
	}
	up.mu.Lock()
	pool := up.pool
	up.pool = nil
	up.mu.Unlock()
	if pool != nil {
		go pool.Close()
	}
}

func (m *poolManager) build(ctx context.Context, pgUser, password, database string) (*pgxpool.Pool, error) {
	sslmode := "disable"
	if m.backendTLS {
		sslmode = "require"
	}
	connStr := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(pgUser, password),
		Host:     m.backend,
		Path:     "/" + database,
		RawQuery: "sslmode=" + sslmode,
	}).String()

	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}
	if m.dialFunc != nil {
		cfg.ConnConfig.DialFunc = m.dialFunc
	}
	if m.lookupFunc != nil {
		cfg.ConnConfig.LookupFunc = m.lookupFunc
	}

	tracerOpts := []otelpgx.Option{otelpgx.WithTrimSQLInSpanName()}
	if m.peerService != "" {
		tracerOpts = append(tracerOpts, otelpgx.WithTracerAttributes(
			attribute.String("peer.service", m.peerService),
		))
	}
	cfg.ConnConfig.Tracer = otelpgx.NewTracer(tracerOpts...)

	cfg.MaxConns = m.maxConns
	cfg.MinConns = 0
	cfg.MaxConnIdleTime = m.idleTimeout
	cfg.MaxConnLifetime = time.Hour

	// Bound every statement server-side. Applied per connection so it holds
	// for catalog reads and user queries alike.
	timeoutMS := int64(m.stmtTimeout / time.Millisecond)
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET statement_timeout = %d", timeoutMS))
		return err
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	// Fail fast on a bad credential rather than at first query.
	pingCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect as %s: %w", pgUser, err)
	}
	return pool, nil
}

// reapIdle closes pools that have gone unused. Because pools hold no session
// state, reaping one is invisible to the user beyond a reconnect.
func (m *poolManager) reapIdle(now time.Time) {
	m.mu.Lock()
	var stale []*userPool
	for key, up := range m.pools {
		up.mu.Lock()
		idle := up.pool != nil && now.Sub(up.lastUsed) > m.idleTimeout
		up.mu.Unlock()
		if idle {
			stale = append(stale, up)
			delete(m.pools, key)
		}
	}
	m.mu.Unlock()

	for _, up := range stale {
		up.mu.Lock()
		pool := up.pool
		up.pool = nil
		up.mu.Unlock()
		if pool != nil {
			pool.Close()
		}
	}
}

func (m *poolManager) run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.closeAll()
			return
		case now := <-t.C:
			m.reapIdle(now)
		}
	}
}

func (m *poolManager) closeAll() {
	m.mu.Lock()
	pools := make([]*userPool, 0, len(m.pools))
	for key, up := range m.pools {
		pools = append(pools, up)
		delete(m.pools, key)
	}
	m.mu.Unlock()
	for _, up := range pools {
		up.mu.Lock()
		if up.pool != nil {
			up.pool.Close()
			up.pool = nil
		}
		up.mu.Unlock()
	}
}

// isAuthFailure reports a stale pooled credential (SQLSTATE 28P01/28000),
// which means another instance rotated this role's password.
func isAuthFailure(err error) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code == "28P01" || pe.Code == "28000"
	}
	return strings.Contains(strings.ToLower(err.Error()), "password authentication failed")
}

// permsFingerprintFor is a test seam over permsFingerprint.
func permsFingerprintFor(perms, schemas []string) string {
	return permsFingerprint(&auth.DBPermissions{Permissions: perms, Schemas: schemas})
}
