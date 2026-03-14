//go:build integration

package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/proxy"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

// mockAuthorizer returns a preconfigured AuthResult or error.
type mockAuthorizer struct {
	result *auth.AuthResult
	err    error
}

func (m *mockAuthorizer) Authorize(_ context.Context, _ string, _ string) (*auth.AuthResult, error) {
	return m.result, m.err
}

// setupProxy spins up testcontainers for Redis and Postgres, creates the
// provisioner and tracker, wires a PostgresProxy with the given mock auth,
// and starts an accept loop on localhost. Returns the proxy listen address.
func setupProxy(t *testing.T, authResult *auth.AuthResult, authErr error) string {
	t.Helper()

	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "proxytest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, backend := testutil.PostgresBackend(t)
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", store, logger)

	p := &proxy.PostgresProxy{
		Backend:      backend,
		Name:         "test-listener",
		Auth:         &mockAuthorizer{result: authResult, err: authErr},
		Tracker:      tracker,
		Provisioner:  provisioner,
		Metrics:      m,
		PGConfig:     &config.PostgresAdmin{},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()

	return ln.Addr().String()
}

// proxyConnect dials the proxy and opens a pgx connection to the given database.
func proxyConnect(t *testing.T, addr, database string) *pgx.Conn {
	t.Helper()
	connStr := fmt.Sprintf("postgres://ignored:ignored@%s/%s?sslmode=disable", addr, database)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		t.Fatalf("proxy connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// proxyConnectErr dials the proxy expecting an error.
func proxyConnectErr(t *testing.T, addr, database string) error {
	t.Helper()
	connStr := fmt.Sprintf("postgres://ignored:ignored@%s/%s?sslmode=disable", addr, database)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		return err
	}
	conn.Close(context.Background())
	t.Fatal("expected connection error but succeeded")
	return nil
}

// adminConn connects directly to the test Postgres as admin.
func adminConn(t *testing.T) *pgx.Conn {
	t.Helper()
	connStr, _ := testutil.PostgresBackend(t)
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// cleanupRole drops a provisioned role.
func cleanupRole(t *testing.T, loginName, nodeName, database string) {
	t.Helper()
	// The provisioner formats usernames as wp_{login}_{node}_{db}.
	// Replicate the logic to predict the role name for cleanup.
	conn := adminConn(t)
	ctx := context.Background()

	// Find all roles with the wp_ prefix matching this identity.
	rows, err := conn.Query(ctx, "SELECT rolname FROM pg_roles WHERE rolname LIKE 'wp_%'")
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var rolname string
		if err := rows.Scan(&rolname); err != nil {
			continue
		}
		sanitized := pgx.Identifier{rolname}.Sanitize()
		conn.Exec(ctx, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", sanitized))
		conn.Exec(ctx, fmt.Sprintf("DROP OWNED BY %s", sanitized))
		conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", sanitized))
	}
}

// makeAuthResult builds an AuthResult with the given database permissions.
func makeAuthResult(database string, perms auth.DBPermissions, limits *auth.LimitsCap) *auth.AuthResult {
	result := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		MatchedRules: []auth.CapRule{
			{
				Backends: []string{"test-listener"},
				PG: &auth.PGCap{
					Databases: map[string]auth.DBPermissions{
						database: perms,
					},
				},
			},
		},
	}
	if limits != nil {
		result.MatchedRules[0].Limits = limits
		result.Limits = auth.MergedLimits{
			MaxConns: limits.MaxConns,
		}
	}
	return result
}

// Ensure redis import is used.
var _ *redis.Client

func TestIntegration_Proxy_SelectAllowed(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, nil)

	addr := setupProxy(t, result, nil)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")

	var val int
	if err := conn.QueryRow(context.Background(), "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("SELECT 1 failed: %v", err)
	}
	if val != 1 {
		t.Fatalf("expected 1, got %d", val)
	}
}

func TestIntegration_Proxy_DatabaseAccessDenied(t *testing.T) {
	// User has permissions only for "other_db", not "waypoint_test".
	result := makeAuthResult("other_db", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, nil)

	addr := setupProxy(t, result, nil)

	err := proxyConnectErr(t, addr, "waypoint_test")
	if err == nil {
		t.Fatal("expected error connecting to unauthorized database")
	}
	if !strings.Contains(err.Error(), "not authorized for database") {
		t.Fatalf("expected 'not authorized for database' error, got: %v", err)
	}
}

func TestIntegration_Proxy_SelectAllowedInsertDenied(t *testing.T) {
	// Create test table via admin.
	aconn := adminConn(t)
	ctx := context.Background()
	_, err := aconn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.acl_test (id int)")
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		c := adminConn(t)
		c.Exec(context.Background(), "DROP TABLE IF EXISTS public.acl_test")
	})

	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{
			"USAGE ON SCHEMA public",
			"SELECT ON public.acl_test",
		},
	}, nil)

	addr := setupProxy(t, result, nil)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")

	// SELECT should succeed.
	_, err = conn.Exec(ctx, "SELECT * FROM public.acl_test")
	if err != nil {
		t.Fatalf("SELECT should succeed: %v", err)
	}

	// INSERT should be denied.
	_, err = conn.Exec(ctx, "INSERT INTO public.acl_test VALUES (1)")
	if err == nil {
		t.Fatal("INSERT should be denied")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected 'permission denied' error, got: %v", err)
	}
}

func TestIntegration_Proxy_ConnectionLimitEnforced(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, &auth.LimitsCap{MaxConns: 1})

	addr := setupProxy(t, result, nil)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	// First connection should succeed.
	conn1 := proxyConnect(t, addr, "waypoint_test")

	var val int
	if err := conn1.QueryRow(context.Background(), "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("first connection SELECT failed: %v", err)
	}

	// Second connection should be rejected.
	err := proxyConnectErr(t, addr, "waypoint_test")
	if err == nil {
		t.Fatal("second connection should be rejected")
	}
	if !strings.Contains(err.Error(), "too many connections") {
		t.Fatalf("expected 'too many connections' error, got: %v", err)
	}
}

func TestIntegration_Proxy_AuthFailure(t *testing.T) {
	addr := setupProxy(t, nil, errors.New("tailscale auth denied"))

	err := proxyConnectErr(t, addr, "waypoint_test")
	if err == nil {
		t.Fatal("expected auth failure error")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected 'authentication failed' error, got: %v", err)
	}
}

func TestIntegration_Proxy_RawSQLPermissions(t *testing.T) {
	// Create test table via admin.
	aconn := adminConn(t)
	ctx := context.Background()
	_, err := aconn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.acl_test (id int)")
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		c := adminConn(t)
		c.Exec(context.Background(), "DROP TABLE IF EXISTS public.acl_test")
	})

	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		SQL: []string{
			"GRANT USAGE ON SCHEMA public TO {role}",
			"GRANT SELECT ON public.acl_test TO {role}",
		},
	}, nil)

	addr := setupProxy(t, result, nil)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")

	// SELECT should succeed via raw SQL grant.
	_, err = conn.Exec(ctx, "SELECT * FROM public.acl_test")
	if err != nil {
		t.Fatalf("SELECT should succeed with SQL grant: %v", err)
	}

	// INSERT should be denied.
	_, err = conn.Exec(ctx, "INSERT INTO public.acl_test VALUES (1)")
	if err == nil {
		t.Fatal("INSERT should be denied")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected 'permission denied' error, got: %v", err)
	}
}
