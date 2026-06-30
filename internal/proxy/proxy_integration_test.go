//go:build integration

package proxy_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
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
	return setupProxyWithClientTLS(t, authResult, authErr, config.PostgresTLSOff, nil)
}

func setupProxyWithClientTLS(t *testing.T, authResult *auth.AuthResult, authErr error, clientTLSMode config.PostgresTLSMode, clientTLS *tls.Config) string {
	t.Helper()

	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "proxytest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, backend := testutil.PostgresBackend(t)
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", false, true, nil, "test", store, logger, nil, nil)

	p := &proxy.PostgresProxy{
		Backend:       backend,
		Name:          "test-listener",
		Auth:          &mockAuthorizer{result: authResult, err: authErr},
		Tracker:       tracker,
		Provisioner:   provisioner,
		Metrics:       m,
		PGConfig:      &config.PostgresAdmin{},
		ClientTLSMode: clientTLSMode,
		ClientTLS:     clientTLS,
		Logger:        logger,
		BytesRead:     &atomic.Int64{},
		BytesWritten:  &atomic.Int64{},
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

func proxyConnectWithQuery(t *testing.T, addr, database, query string) *pgx.Conn {
	t.Helper()
	connStr := fmt.Sprintf("postgres://ignored:ignored@%s/%s?sslmode=disable&%s", addr, database, query)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		t.Fatalf("proxy connect with query %q: %v", query, err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func proxyConnectSSLRequire(t *testing.T, addr, database string) *pgx.Conn {
	t.Helper()
	connStr := fmt.Sprintf("postgres://ignored:ignored@%s/%s?sslmode=require", addr, database)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		t.Fatalf("proxy connect with sslmode=require: %v", err)
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

func proxyConnectErrWithSSLMode(t *testing.T, addr, database, sslmode string) error {
	t.Helper()
	connStr := fmt.Sprintf("postgres://ignored:ignored@%s/%s?sslmode=%s", addr, database, sslmode)
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
				Backends: map[string]auth.BackendCap{
					"test-listener": {
						PG: &auth.PGCap{
							Databases: map[string]auth.DBPermissions{
								database: perms,
							},
						},
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
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", false, true, nil, "test", store, logger, nil, nil)

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

func mustTestServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// Ensure redis import is used.
var _ *redis.Client

func TestIntegration_Proxy_SSLModeRequireAllowed(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readonly"},
	}, nil)

	addr := setupProxyWithClientTLS(t, result, nil, config.PostgresTLSOptional, mustTestServerTLSConfig(t))
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnectSSLRequire(t, addr, "waypoint_test")

	var val int
	if err := conn.QueryRow(context.Background(), "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("SELECT 1 failed over TLS: %v", err)
	}
	if val != 1 {
		t.Fatalf("expected 1, got %d", val)
	}
}

func TestIntegration_Proxy_TLSRequiredRejectsPlaintext(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readonly"},
	}, nil)

	addr := setupProxyWithClientTLS(t, result, nil, config.PostgresTLSRequire, mustTestServerTLSConfig(t))
	err := proxyConnectErrWithSSLMode(t, addr, "waypoint_test", "disable")
	if err == nil {
		t.Fatal("expected plaintext connection to fail")
	}
}

func TestIntegration_Proxy_SelectAllowed(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readonly"},
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
		Permissions: []string{"readonly"},
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
		SQL: []string{
			"GRANT USAGE ON SCHEMA public TO {{.Role}}",
			"GRANT SELECT ON public.acl_test TO {{.Role}}",
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

func TestIntegration_Proxy_PresetQueryParamLimitsReadwriteGrant(t *testing.T) {
	cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test")
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	aconn := adminConn(t)
	ctx := context.Background()
	_, err := aconn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.acl_preset_limit (id int)")
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		c := adminConn(t)
		c.Exec(context.Background(), "DROP TABLE IF EXISTS public.acl_preset_limit")
	})

	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readwrite"},
	}, nil)

	addr := setupProxy(t, result, nil)

	readwriteConn := proxyConnect(t, addr, "waypoint_test")
	if _, err := readwriteConn.Exec(ctx, "INSERT INTO public.acl_preset_limit VALUES (1)"); err != nil {
		t.Fatalf("readwrite insert should succeed: %v", err)
	}
	readwriteConn.Close(ctx)

	readonlyConn := proxyConnectWithQuery(t, addr, "waypoint_test", "waypoint_presets=readonly")
	if _, err := readonlyConn.Exec(ctx, "SELECT * FROM public.acl_preset_limit"); err != nil {
		t.Fatalf("readonly select should succeed: %v", err)
	}

	_, err = readonlyConn.Exec(ctx, "INSERT INTO public.acl_preset_limit VALUES (2)")
	if err == nil {
		t.Fatal("readonly preset limit should deny insert")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied error, got: %v", err)
	}
}

func TestIntegration_Proxy_ConnectionLimitEnforced(t *testing.T) {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readonly"},
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
		Permissions: []string{"readonly"},
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
		Permissions: []string{"readonly"},
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
		Permissions: []string{"readonly"},
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
		Permissions: []string{"readonly"},
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
	aconn := adminConn(t)
	ctx := context.Background()
	_, err := aconn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.reval_revoked_test (id int)")
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		c := adminConn(t)
		c.Exec(context.Background(), "DROP TABLE IF EXISTS public.reval_revoked_test")
	})

	// Start with access to waypoint_test.
	initialResult := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readwrite"},
	}, nil)

	dynAuth := &dynamicMockAuthorizer{result: initialResult}

	addr := setupProxyWithAuth(t, dynAuth, func(p *proxy.PostgresProxy) {
		p.RevalInterval = 500 * time.Millisecond
	})
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")

	if _, err := conn.Exec(ctx, "INSERT INTO public.reval_revoked_test VALUES (1)"); err != nil {
		t.Fatalf("initial insert failed: %v", err)
	}

	// Switch auth to return a result that grants access to a different database only.
	// Auth succeeds for the listener, but DatabasePermissions("waypoint_test") returns nil.
	revokedResult := makeAuthResult("other_db", auth.DBPermissions{
		Permissions: []string{"readonly"},
	}, nil)
	dynAuth.SetResult(revokedResult, nil)

	// Wait for revalidation to fire and close the connection.
	time.Sleep(2 * time.Second)

	// The connection should be closed: the caller is no longer authorized for
	// this specific database, so Waypoint terminates the session rather than
	// leaving a privilege-less connection occupying the slot.
	var val int
	err = conn.QueryRow(ctx, "SELECT 1").Scan(&val)
	if err == nil {
		t.Fatal("expected connection to be closed after database permissions were revoked")
	}
}

func TestIntegration_Proxy_RevalidationReconcilesPermissionDowngrade(t *testing.T) {
	aconn := adminConn(t)
	ctx := context.Background()
	_, err := aconn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.reval_downgrade_test (id int)")
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		c := adminConn(t)
		c.Exec(context.Background(), "DROP TABLE IF EXISTS public.reval_downgrade_test")
	})

	initialResult := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readwrite"},
	}, nil)
	dynAuth := &dynamicMockAuthorizer{result: initialResult}

	addr := setupProxyWithAuth(t, dynAuth, func(p *proxy.PostgresProxy) {
		p.RevalInterval = 500 * time.Millisecond
	})
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")
	if _, err := conn.Exec(ctx, "INSERT INTO public.reval_downgrade_test VALUES (1)"); err != nil {
		t.Fatalf("initial insert failed: %v", err)
	}

	downgradedResult := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readonly"},
	}, nil)
	dynAuth.SetResult(downgradedResult, nil)

	time.Sleep(2 * time.Second)

	if _, err := conn.Exec(ctx, "SELECT * FROM public.reval_downgrade_test"); err != nil {
		t.Fatalf("select should still succeed after downgrade: %v", err)
	}
	_, err = conn.Exec(ctx, "INSERT INTO public.reval_downgrade_test VALUES (2)")
	if err == nil {
		t.Fatal("insert should be denied after downgrade to readonly")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied error, got: %v", err)
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
// starts an accept loop, and returns the proxy listen address and proxy struct.
func setupTCPProxy(t *testing.T, backend string, authorizer proxy.Authorizer) (string, *proxy.TCPProxy) {
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

	return ln.Addr().String(), p
}

func TestIntegration_TCPProxy_HappyPath(t *testing.T) {
	echoAddr := startEchoServer(t)

	authResult := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		Limits:    auth.MergedLimits{MaxConns: 10},
	}
	addr, p := setupTCPProxy(t, echoAddr, &mockAuthorizer{result: authResult})

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

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

	// Close connection and wait for relay to finish recording bytes.
	conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for p.BytesRead.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if br := p.BytesRead.Load(); br == 0 {
		t.Error("expected BytesRead > 0 after TCP echo")
	}
	if bw := p.BytesWritten.Load(); bw == 0 {
		t.Error("expected BytesWritten > 0 after TCP echo")
	}
}

func TestIntegration_TCPProxy_AuthFailure(t *testing.T) {
	echoAddr := startEchoServer(t)

	addr, _ := setupTCPProxy(t, echoAddr, &mockAuthorizer{err: errors.New("tcp auth denied")})

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
	addr, _ := setupTCPProxy(t, echoAddr, &mockAuthorizer{result: authResult})

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
		Limits: &auth.LimitsCap{MaxConns: 5},
		Backends: map[string]auth.BackendCap{
			"test-listener": {
				PG: &auth.PGCap{
					Databases: map[string]auth.DBPermissions{
						"waypoint_test": {
							Permissions: []string{"readonly"},
						},
					},
				},
			},
		},
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
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", false, true, nil, "test", store, logger, nil, nil)

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
	addr, _ := setupTCPProxy(t, echoAddr, &mockAuthorizer{result: authResult})

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
		Permissions: []string{"readonly"},
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
	provisioner := provision.NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", false, true, nil, "test", store, lgr, nil, nil)

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

// TestIntegration_TCPProxy_PortMap loads a TOML config with port_map,
// verifies ExpandedBackends produces correct pairs, then wires up a
// TCPProxy for each pair and verifies data flows on every mapped port.
// This catches the original bug where TOML's string-keyed maps silently
// produced an empty PortMap, resulting in only a single backend pair.
func TestIntegration_TCPProxy_PortMap(t *testing.T) {
	// Start two independent echo servers (simulating a multi-port backend).
	echo1Addr := startEchoServer(t)
	echo2Addr := startEchoServer(t)

	// Extract the ports from the echo server addresses.
	_, echo1Port, _ := net.SplitHostPort(echo1Addr)
	_, echo2Port, _ := net.SplitHostPort(echo2Addr)

	// Build and load a TOML config with port_map.
	tomlContent := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-portmap-test"

[[listeners]]
name = "multi-port"
mode = "tcp"
backend = "127.0.0.1"
port_map = { "10001" = %s, "10002" = %s }
`, echo1Port, echo2Port)

	dir := t.TempDir()
	configPath := filepath.Join(dir, "waypoint.toml")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load config: %v", err)
	}

	l := cfg.Listeners[0]

	// Verify PortMap was populated from TOML (the original bug: this was empty).
	if len(l.PortMap) != 2 {
		t.Fatalf("PortMap len = %d, want 2 (port_map parsing may have silently failed)", len(l.PortMap))
	}

	backends := l.ExpandedBackends()
	if len(backends) != 2 {
		t.Fatalf("ExpandedBackends returned %d pairs, want 2", len(backends))
	}

	// Wire up a TCPProxy for each expanded backend and verify echo works.
	authResult := &auth.AuthResult{
		LoginName: "portmap-test@example.com",
		NodeName:  "test-node",
		Limits:    auth.MergedLimits{MaxConns: 10},
	}

	for _, be := range backends {
		be := be
		t.Run(be.Listen, func(t *testing.T) {
			addr, _ := setupTCPProxy(t, be.Backend, &mockAuthorizer{result: authResult})

			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()

			msg := fmt.Sprintf("echo-portmap-%s\n", be.Listen)
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
				t.Fatalf("echo mismatch: got %q, want %q", string(buf[:n]), msg)
			}
		})
	}
}
