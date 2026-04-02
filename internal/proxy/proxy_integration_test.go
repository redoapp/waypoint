//go:build integration

package proxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
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
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", store, logger, nil, nil)

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
			MaxConns:        limits.MaxConns,
			MaxBytesPerConn: limits.MaxBytesPerConn,
		}
		if limits.MaxConnDuration != "" {
			d, _ := time.ParseDuration(limits.MaxConnDuration)
			result.Limits.MaxConnDuration = d
		}
		for _, bw := range limits.Bandwidth {
			p, _ := time.ParseDuration(bw.Period)
			result.Limits.BandwidthTiers = append(result.Limits.BandwidthTiers, auth.BandwidthTier{
				Bytes: bw.Bytes, Period: p,
			})
		}
	}
	return result
}

// dynamicMockAuthorizer is a thread-safe mock whose response can change mid-test.
type dynamicMockAuthorizer struct {
	mu     sync.Mutex
	result *auth.AuthResult
	err    error
}

func (m *dynamicMockAuthorizer) Authorize(_ context.Context, _ string, _ string) (*auth.AuthResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.result, m.err
}

func (m *dynamicMockAuthorizer) SetResult(result *auth.AuthResult, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.result = result
	m.err = err
}

// setupProxyWithAuth is like setupProxy but accepts any proxy.Authorizer and
// functional options for configuring the proxy (e.g. RevalInterval).
func setupProxyWithAuth(t *testing.T, authorizer proxy.Authorizer, opts ...func(*proxy.PostgresProxy)) string {
	t.Helper()

	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "proxytest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, backend := testutil.PostgresBackend(t)
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", store, logger, nil, nil)

	p := &proxy.PostgresProxy{
		Backend:      backend,
		Name:         "test-listener",
		Auth:         authorizer,
		Tracker:      tracker,
		Provisioner:  provisioner,
		Metrics:      m,
		PGConfig:     &config.PostgresAdmin{},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}
	for _, opt := range opts {
		opt(p)
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
			"GRANT USAGE ON SCHEMA public TO {{.Role}}",
			"GRANT SELECT ON public.acl_test TO {{.Role}}",
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

func TestIntegration_Proxy_ByteLimitEnforced(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, &auth.LimitsCap{MaxConns: 10, MaxBytesPerConn: 1024})

	addr := setupProxy(t, result, nil)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")
	ctx := context.Background()

	// Generate a response larger than 1024 bytes to exceed the byte limit.
	_, err := conn.Exec(ctx, "SELECT repeat('x', 2000)")
	if err != nil {
		// Some drivers may fail on the large response itself; that's acceptable.
		t.Logf("large query returned error (expected): %v", err)
	}

	// The connection should now be terminated due to byte limit.
	var val int
	err = conn.QueryRow(ctx, "SELECT 1").Scan(&val)
	if err == nil {
		t.Fatal("expected connection to be terminated after exceeding byte limit")
	}
}

func TestIntegration_Proxy_DurationLimitEnforced(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, &auth.LimitsCap{MaxConns: 10, MaxConnDuration: "2s"})

	addr := setupProxy(t, result, nil)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")
	ctx := context.Background()

	// Connection should work initially.
	var val int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("initial SELECT 1 failed: %v", err)
	}

	// Wait for duration limit to expire.
	time.Sleep(3 * time.Second)

	// Next query should fail because the connection duration exceeded the limit.
	err := conn.QueryRow(ctx, "SELECT 1").Scan(&val)
	if err == nil {
		t.Fatal("expected connection to be terminated after exceeding duration limit")
	}
}

func TestIntegration_Proxy_MidSessionRevalidation(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, nil)

	dynAuth := &dynamicMockAuthorizer{result: result}

	addr := setupProxyWithAuth(t, dynAuth, func(p *proxy.PostgresProxy) {
		p.RevalInterval = 500 * time.Millisecond
	})
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")
	ctx := context.Background()

	// Connection should work initially.
	var val int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("initial SELECT 1 failed: %v", err)
	}

	// Revoke access mid-session.
	dynAuth.SetResult(nil, errors.New("access revoked"))

	// Wait for revalidation to fire and close the connection.
	time.Sleep(2 * time.Second)

	// Next query should fail because the revalidation loop closed the connection.
	err := conn.QueryRow(ctx, "SELECT 1").Scan(&val)
	if err == nil {
		t.Fatal("expected connection to be closed after revalidation revoked access")
	}
}

func TestIntegration_Proxy_WildcardDatabaseAccess(t *testing.T) {
	result := makeAuthResult("*", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, nil)

	addr := setupProxy(t, result, nil)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")

	var val int
	if err := conn.QueryRow(context.Background(), "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("SELECT 1 with wildcard database access failed: %v", err)
	}
	if val != 1 {
		t.Fatalf("expected 1, got %d", val)
	}
}

func TestIntegration_Proxy_RevalidationPermissionRevoked(t *testing.T) {
	// Start with access to waypoint_test.
	initialResult := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, nil)

	dynAuth := &dynamicMockAuthorizer{result: initialResult}

	addr := setupProxyWithAuth(t, dynAuth, func(p *proxy.PostgresProxy) {
		p.RevalInterval = 500 * time.Millisecond
	})
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")
	ctx := context.Background()

	// Connection should work initially.
	var val int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("initial SELECT 1 failed: %v", err)
	}

	// Switch auth to return a result that grants access to a different database only.
	// Auth succeeds, but DatabasePermissions("waypoint_test") returns nil.
	revokedResult := makeAuthResult("other_db", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, nil)
	dynAuth.SetResult(revokedResult, nil)

	// Wait for revalidation to fire and close the connection.
	time.Sleep(2 * time.Second)

	// Next query should fail because permissions were revoked.
	err := conn.QueryRow(ctx, "SELECT 1").Scan(&val)
	if err == nil {
		t.Fatal("expected connection to be closed after database permissions revoked")
	}
}

// startEchoServer starts a TCP server that echoes back everything it receives.
// Returns the listen address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// setupTCPProxy creates a TCPProxy wired to the given backend and auth,
// starts an accept loop, and returns the proxy listen address.
func setupTCPProxy(t *testing.T, backend string, authorizer proxy.Authorizer) string {
	t.Helper()

	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "tcpproxytest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	p := &proxy.TCPProxy{
		Backend:      backend,
		Name:         "test-tcp-listener",
		Auth:         authorizer,
		Tracker:      tracker,
		Metrics:      m,
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

func TestIntegration_TCPProxy_HappyPath(t *testing.T) {
	echoAddr := startEchoServer(t)

	authResult := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		Limits:    auth.MergedLimits{MaxConns: 10},
	}
	addr := setupTCPProxy(t, echoAddr, &mockAuthorizer{result: authResult})

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	msg := "hello from tcp proxy test\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != msg {
		t.Fatalf("expected echo %q, got %q", msg, string(buf[:n]))
	}
}

func TestIntegration_TCPProxy_AuthFailure(t *testing.T) {
	echoAddr := startEchoServer(t)

	addr := setupTCPProxy(t, echoAddr, &mockAuthorizer{err: errors.New("tcp auth denied")})

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// The proxy should close the connection after auth failure.
	// Try to read — should get EOF.
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed after auth failure")
	}
}

func TestIntegration_TCPProxy_ConnectionLimitEnforced(t *testing.T) {
	echoAddr := startEchoServer(t)

	authResult := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		Limits:    auth.MergedLimits{MaxConns: 1},
	}
	addr := setupTCPProxy(t, echoAddr, &mockAuthorizer{result: authResult})

	// First connection should succeed — verify with echo.
	conn1, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy (conn1): %v", err)
	}
	defer conn1.Close()

	msg := "test\n"
	if _, err := conn1.Write([]byte(msg)); err != nil {
		t.Fatalf("write conn1: %v", err)
	}
	buf := make([]byte, len(msg))
	conn1.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn1, buf); err != nil {
		t.Fatalf("read conn1: %v", err)
	}

	// Second connection should be rejected (closed immediately).
	conn2, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy (conn2): %v", err)
	}
	defer conn2.Close()

	conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn2.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected second connection to be closed due to limit")
	}
}

// startTailscaleControl starts a testcontrol.Server with DERP and STUN.
func startTailscaleControl(t *testing.T) (controlURL string, control *testcontrol.Server) {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpLogf := logger.Discard
	derpMap := integration.RunDERPAndSTUN(t, derpLogf, "127.0.0.1")
	control = &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
		},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL = control.HTTPTestServer.URL
	return controlURL, control
}

// startTSNode starts a tsnet.Server connected to the given control URL.
func startTSNode(t *testing.T, ctx context.Context, controlURL, hostname string) *tsnet.Server {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), hostname)
	os.MkdirAll(tmp, 0755)
	s := &tsnet.Server{
		Dir:        tmp,
		ControlURL: controlURL,
		Hostname:   hostname,
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { s.Close() })

	if _, err := s.Up(ctx); err != nil {
		t.Fatalf("tsnet %s Up: %v", hostname, err)
	}
	return s
}

func TestIntegration_TailscaleAuthorizer_RealPipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	controlURL, control := startTailscaleControl(t)

	// Set waypoint capabilities for all peers.
	capRule := auth.CapRule{
		Backends: []string{"test-listener"},
		PG: &auth.PGCap{
			Databases: map[string]auth.DBPermissions{
				"waypoint_test": {
					Permissions: []string{"USAGE ON SCHEMA public"},
				},
			},
		},
		Limits: &auth.LimitsCap{MaxConns: 5},
	}
	capJSON, err := json.Marshal(capRule)
	if err != nil {
		t.Fatalf("marshal cap rule: %v", err)
	}
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{
		tailcfg.PeerCapability(auth.WaypointCap): {tailcfg.RawMessage(capJSON)},
	})

	// Start two tsnet nodes: proxyNode hosts the proxy, clientNode connects through it.
	proxyNode := startTSNode(t, ctx, controlURL, "proxy-server")
	clientNode := startTSNode(t, ctx, controlURL, "client-node")

	// Get the proxy node's LocalClient for WhoIs.
	proxyLC, err := proxyNode.LocalClient()
	if err != nil {
		t.Fatalf("proxy LocalClient: %v", err)
	}
	authorizer := &proxy.TailscaleAuthorizer{LC: proxyLC, Logger: slog.Default()}

	// Listen on the proxy node's tailnet address.
	ln, err := proxyNode.Listen("tcp", ":5432")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Wire up the proxy with the real TailscaleAuthorizer.
	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "tstest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_, backend := testutil.PostgresBackend(t)
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", store, logger, nil, nil)

	p := &proxy.PostgresProxy{
		Backend:      backend,
		Name:         "test-listener",
		Auth:         authorizer,
		Tracker:      tracker,
		Provisioner:  provisioner,
		Metrics:      m,
		PGConfig:     &config.PostgresAdmin{},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()

	// Connect from the client node through the proxy.
	proxyStatus, err := proxyLC.Status(ctx)
	if err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	proxyIP := proxyStatus.TailscaleIPs[0]

	connStr := fmt.Sprintf("postgres://ignored:ignored@%s:5432/waypoint_test?sslmode=disable", proxyIP)
	clientConn, err := clientNode.Dial(ctx, "tcp", fmt.Sprintf("%s:5432", proxyIP))
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer clientConn.Close()

	// Use pgx over the tsnet connection.
	pgCfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pgCfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return clientNode.Dial(ctx, "tcp", fmt.Sprintf("%s:5432", proxyIP))
	}
	pgConn, err := pgx.ConnectConfig(ctx, pgCfg)
	if err != nil {
		t.Fatalf("pgx connect: %v", err)
	}
	selfUser := proxyStatus.User[proxyStatus.Self.UserID]
	t.Cleanup(func() {
		pgConn.Close(context.Background())
		cleanupRole(t, selfUser.LoginName, proxyStatus.Self.HostName, "waypoint_test")
	})

	var val int
	if err := pgConn.QueryRow(ctx, "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("SELECT 1 failed: %v", err)
	}
	if val != 1 {
		t.Fatalf("expected 1, got %d", val)
	}
}

func TestIntegration_TCPProxy_CustomDialer(t *testing.T) {
	echoAddr := startEchoServer(t)

	var dialerCalled atomic.Bool
	customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialerCalled.Store(true)
		return net.DialTimeout(network, addr, 10*time.Second)
	}

	authResult := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		Limits:    auth.MergedLimits{MaxConns: 10},
	}

	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "tcpdialer:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	p := &proxy.TCPProxy{
		Backend:      echoAddr,
		Name:         "test-tcp-dialer",
		Auth:         &mockAuthorizer{result: authResult},
		Tracker:      tracker,
		Metrics:      m,
		Logger:       logger,
		Dialer:       customDialer,
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

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	msg := "hello custom dialer\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("expected echo %q, got %q", msg, string(buf))
	}

	if !dialerCalled.Load() {
		t.Fatal("expected custom dialer to be called")
	}
}

func TestIntegration_TCPProxy_DefaultDialer(t *testing.T) {
	echoAddr := startEchoServer(t)

	authResult := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		Limits:    auth.MergedLimits{MaxConns: 10},
	}
	// Dialer is nil — should fall back to net.DialTimeout.
	addr := setupTCPProxy(t, echoAddr, &mockAuthorizer{result: authResult})

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	msg := "hello default dialer\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("expected echo %q, got %q", msg, string(buf))
	}
}

func TestIntegration_PostgresProxy_CustomDialer(t *testing.T) {
	var dialerCalled atomic.Bool
	customDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialerCalled.Store(true)
		return net.DialTimeout(network, addr, 10*time.Second)
	}

	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"USAGE ON SCHEMA public"},
	}, nil)

	addr := setupProxyWithAuth(t, &mockAuthorizer{result: result}, func(p *proxy.PostgresProxy) {
		p.Dialer = customDialer
	})
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")

	var val int
	if err := conn.QueryRow(context.Background(), "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("SELECT 1 failed: %v", err)
	}
	if val != 1 {
		t.Fatalf("expected 1, got %d", val)
	}

	if !dialerCalled.Load() {
		t.Fatal("expected custom dialer to be called for PostgresProxy")
	}
}

func TestIntegration_BackendViaTailscale(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	controlURL, _ := startTailscaleControl(t)

	// Start 3 tsnet nodes.
	proxyNode := startTSNode(t, ctx, controlURL, "proxy-node")
	clientNode := startTSNode(t, ctx, controlURL, "client-node")
	backendNode := startTSNode(t, ctx, controlURL, "backend-node")

	// Start a TCP echo server on the backend node, accessible only via Tailscale.
	backendLn, err := backendNode.Listen("tcp", ":9999")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	t.Cleanup(func() { backendLn.Close() })

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	// Get backend node's Tailscale IP.
	backendLC, err := backendNode.LocalClient()
	if err != nil {
		t.Fatalf("backend LocalClient: %v", err)
	}
	backendStatus, err := backendLC.Status(ctx)
	if err != nil {
		t.Fatalf("backend status: %v", err)
	}
	backendIP := backendStatus.TailscaleIPs[0]
	backendAddr := fmt.Sprintf("%s:9999", backendIP)

	// Set up the proxy with proxyNode.Dial as the dialer.
	proxyLC, err := proxyNode.LocalClient()
	if err != nil {
		t.Fatalf("proxy LocalClient: %v", err)
	}

	authResult := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		Limits:    auth.MergedLimits{MaxConns: 10},
	}

	// Set up capabilities so the TailscaleAuthorizer would work,
	// but we use a mock here for simplicity.
	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "tsbackend:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	p := &proxy.TCPProxy{
		Backend:      backendAddr,
		Name:         "test-ts-backend",
		Auth:         &mockAuthorizer{result: authResult},
		Tracker:      tracker,
		Metrics:      m,
		Logger:       lgr,
		Dialer:       proxyNode.Dial,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	// Listen on the proxy node for inbound connections.
	proxyLn, err := proxyNode.Listen("tcp", ":8888")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { proxyLn.Close() })

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()

	// From clientNode, dial the proxy and verify echo.
	proxyStatus, err := proxyLC.Status(ctx)
	if err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	proxyIP := proxyStatus.TailscaleIPs[0]

	conn, err := clientNode.Dial(ctx, "tcp", fmt.Sprintf("%s:8888", proxyIP))
	if err != nil {
		t.Fatalf("client dial proxy: %v", err)
	}
	defer conn.Close()

	msg := "hello via tailscale backend\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != msg {
		t.Fatalf("expected echo %q, got %q", msg, string(buf[:n]))
	}
}

func TestIntegration_TailscaleAuthorizer_NoCapability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start control without any waypoint capabilities.
	controlURL, _ := startTailscaleControl(t)

	proxyNode := startTSNode(t, ctx, controlURL, "proxy-server")
	clientNode := startTSNode(t, ctx, controlURL, "client-node")

	proxyLC, err := proxyNode.LocalClient()
	if err != nil {
		t.Fatalf("proxy LocalClient: %v", err)
	}
	authorizer := &proxy.TailscaleAuthorizer{LC: proxyLC, Logger: slog.Default()}

	ln, err := proxyNode.Listen("tcp", ":5432")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "tstest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_, backend := testutil.PostgresBackend(t)
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", store, lgr, nil, nil)

	p := &proxy.PostgresProxy{
		Backend:      backend,
		Name:         "test-listener",
		Auth:         authorizer,
		Tracker:      tracker,
		Provisioner:  provisioner,
		Metrics:      m,
		PGConfig:     &config.PostgresAdmin{},
		Logger:       lgr,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()

	proxyStatus, err := proxyLC.Status(ctx)
	if err != nil {
		t.Fatalf("proxy status: %v", err)
	}
	proxyIP := proxyStatus.TailscaleIPs[0]

	connStr := fmt.Sprintf("postgres://ignored:ignored@%s:5432/waypoint_test?sslmode=disable", proxyIP)
	pgCfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pgCfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return clientNode.Dial(ctx, "tcp", fmt.Sprintf("%s:5432", proxyIP))
	}

	_, err = pgx.ConnectConfig(ctx, pgCfg)
	if err == nil {
		t.Fatal("expected error connecting without capabilities")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected 'authentication failed' error, got: %v", err)
	}
}

// setNodeTags sets ACL tags on a tsnet node via the test control plane and
// waits for the node to see the updated tags.
func setNodeTags(t *testing.T, ctx context.Context, control *testcontrol.Server, srv *tsnet.Server, tags []string) {
	t.Helper()
	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatalf("local client: %v", err)
	}
	st, err := lc.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	nodeKey := st.Self.PublicKey
	node := control.Node(nodeKey)
	if node == nil {
		t.Fatal("node not found in control")
	}
	node.Tags = tags
	control.UpdateNode(node)

	// Wait for the node to see its updated tags.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, err = lc.Status(ctx)
		if err != nil {
			t.Fatalf("status poll: %v", err)
		}
		if st.Self.Tags != nil && st.Self.Tags.Len() > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for node to see its tags")
}

// startTaggedTSNode starts a tsnet.Server and assigns it ACL tags via the control plane.
func startTaggedTSNode(t *testing.T, ctx context.Context, controlURL string, control *testcontrol.Server, hostname string, tags []string) *tsnet.Server {
	t.Helper()
	srv := startTSNode(t, ctx, controlURL, hostname)
	setNodeTags(t, ctx, control, srv, tags)
	return srv
}

// TestIntegration_ListenService_TaggedNode verifies that ListenService succeeds
// on a tagged node and that the returned ServiceListener works as a net.Listener.
func TestIntegration_ListenService_TaggedNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	controlURL, control := startTailscaleControl(t)

	proxyNode := startTaggedTSNode(t, ctx, controlURL, control, "svc-proxy", []string{"tag:waypoint"})

	svcLn, err := proxyNode.ListenService("svc:echo-test", tsnet.ServiceModeTCP{Port: 7777})
	if err != nil {
		t.Fatalf("ListenService: %v", err)
	}
	defer svcLn.Close()

	// Verify the ServiceListener has a valid FQDN.
	if svcLn.FQDN == "" {
		t.Error("expected non-empty FQDN on ServiceListener")
	}
	t.Logf("service FQDN: %s", svcLn.FQDN)

	// Verify the ServiceListener works as a net.Listener by connecting
	// to its local address directly.
	go func() {
		conn, err := svcLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	localAddr := svcLn.Listener.Addr().String()
	conn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial local listener: %v", err)
	}
	defer conn.Close()

	msg := "hello-service"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.(*net.TCPConn).CloseWrite()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("echo = %q, want %q", buf, msg)
	}
}

// TestIntegration_ListenService_UntaggedNodeFails verifies that ListenService
// returns ErrUntaggedServiceHost when the node has no ACL tags.
func TestIntegration_ListenService_UntaggedNodeFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	controlURL, _ := startTailscaleControl(t)

	// Start a node without tags.
	untaggedNode := startTSNode(t, ctx, controlURL, "svc-untagged")

	_, err := untaggedNode.ListenService("svc:test", tsnet.ServiceModeTCP{Port: 9999})
	if !errors.Is(err, tsnet.ErrUntaggedServiceHost) {
		t.Fatalf("expected ErrUntaggedServiceHost, got: %v", err)
	}
}

// TestIntegration_ListenService_MultiInstance verifies that multiple tagged nodes
// can each register as hosts for the same Tailscale Service name.
func TestIntegration_ListenService_MultiInstance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	controlURL, control := startTailscaleControl(t)

	proxyNode1 := startTaggedTSNode(t, ctx, controlURL, control, "svc-proxy-1", []string{"tag:waypoint"})
	proxyNode2 := startTaggedTSNode(t, ctx, controlURL, control, "svc-proxy-2", []string{"tag:waypoint"})

	// Both nodes register the same service.
	svcLn1, err := proxyNode1.ListenService("svc:echo-multi", tsnet.ServiceModeTCP{Port: 8888})
	if err != nil {
		t.Fatalf("ListenService proxy1: %v", err)
	}
	defer svcLn1.Close()

	svcLn2, err := proxyNode2.ListenService("svc:echo-multi", tsnet.ServiceModeTCP{Port: 8888})
	if err != nil {
		t.Fatalf("ListenService proxy2: %v", err)
	}
	defer svcLn2.Close()

	// Each echo server tags its responses to identify the instance.
	serveEchoTagged := func(ln net.Listener, tag string) {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				conn.Write([]byte(tag + ":" + string(buf[:n])))
			}()
		}
	}
	go serveEchoTagged(svcLn1, "node1")
	go serveEchoTagged(svcLn2, "node2")

	// Connect to each local listener and verify distinct responses.
	checkInstance := func(svcLn *tsnet.ServiceListener, expectedTag string) {
		t.Helper()
		localAddr := svcLn.Listener.Addr().String()
		conn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %s: %v", expectedTag, err)
		}
		defer conn.Close()

		msg := "ping"
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("write %s: %v", expectedTag, err)
		}
		conn.(*net.TCPConn).CloseWrite()

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %s: %v", expectedTag, err)
		}
		resp := string(buf[:n])
		expected := expectedTag + ":" + msg
		if resp != expected {
			t.Errorf("%s: got %q, want %q", expectedTag, resp, expected)
		}
	}

	checkInstance(svcLn1, "node1")
	checkInstance(svcLn2, "node2")

	// Both FQDNs should match since they're the same service.
	if svcLn1.FQDN != svcLn2.FQDN {
		t.Errorf("FQDNs should match: %q vs %q", svcLn1.FQDN, svcLn2.FQDN)
	}
	t.Logf("both instances registered as %s", svcLn1.FQDN)
}
