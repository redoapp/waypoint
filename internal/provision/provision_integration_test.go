//go:build integration

package provision

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

func setupProvisioner(t *testing.T) *Provisioner {
	t.Helper()
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	_, backend := testutil.PostgresBackend(t)
	return NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", store, logger)
}

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

func TestIntegration_EnsureUser_CreatesRole(t *testing.T) {
	p := setupProvisioner(t)
	ctx := context.Background()

	pgUser, _, err := p.EnsureUser(ctx, "alice@example.com", "alice-laptop", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify role exists in pg_roles.
	conn := adminConn(t)
	var exists bool
	err = conn.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", pgUser).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("role %q should exist in pg_roles", pgUser)
	}
}

func TestIntegration_EnsureUser_CanLogin(t *testing.T) {
	p := setupProvisioner(t)
	ctx := context.Background()
	_, backend := testutil.PostgresBackend(t)

	pgUser, password, err := p.EnsureUser(ctx, "bob@example.com", "bob-desktop", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Connect as the provisioned user.
	userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, backend)
	userConn, err := pgx.Connect(ctx, userConnStr)
	if err != nil {
		t.Fatalf("login as provisioned user failed: %v", err)
	}
	defer userConn.Close(ctx)

	// Verify we're connected as the right user.
	var currentUser string
	if err := userConn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser); err != nil {
		t.Fatal(err)
	}
	if currentUser != pgUser {
		t.Fatalf("expected current_user=%q, got %q", pgUser, currentUser)
	}
}

func TestIntegration_EnsureUser_UpdatesPassword(t *testing.T) {
	p := setupProvisioner(t)
	ctx := context.Background()
	_, backend := testutil.PostgresBackend(t)

	pgUser, password1, err := p.EnsureUser(ctx, "carol@example.com", "carol-laptop", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Call again — should rotate password.
	_, password2, err := p.EnsureUser(ctx, "carol@example.com", "carol-laptop", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}

	if password1 == password2 {
		t.Fatal("expected different passwords on second EnsureUser call")
	}

	// Old password should fail.
	oldConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password1, backend)
	_, err = pgx.Connect(ctx, oldConnStr)
	if err == nil {
		t.Fatal("old password should not work after rotation")
	}

	// New password should work.
	newConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password2, backend)
	conn, err := pgx.Connect(ctx, newConnStr)
	if err != nil {
		t.Fatalf("new password should work: %v", err)
	}
	conn.Close(ctx)
}

func TestIntegration_EnsureUser_GrantConnect(t *testing.T) {
	p := setupProvisioner(t)
	ctx := context.Background()

	pgUser, _, err := p.EnsureUser(ctx, "dave@example.com", "dave-node", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify CONNECT privilege.
	conn := adminConn(t)
	var hasConnect bool
	err = conn.QueryRow(ctx,
		"SELECT has_database_privilege($1, 'waypoint_test', 'CONNECT')", pgUser).Scan(&hasConnect)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConnect {
		t.Fatalf("role %q should have CONNECT on waypoint_test", pgUser)
	}
}

func TestIntegration_EnsureUser_ConcurrentPasswordRotation(t *testing.T) {
	p := setupProvisioner(t)
	ctx := context.Background()
	_, backend := testutil.PostgresBackend(t)

	// First call to create the role.
	pgUser, _, err := p.EnsureUser(ctx, "concurrent@example.com", "conc-node", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn := adminConn(t)
		c := context.Background()
		s := pgx.Identifier{pgUser}.Sanitize()
		conn.Exec(c, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", s))
		conn.Exec(c, fmt.Sprintf("DROP OWNED BY %s", s))
		conn.Exec(c, fmt.Sprintf("DROP ROLE IF EXISTS %s", s))
	})

	// Race two EnsureUser calls for the same identity.
	type result struct {
		password string
		err      error
	}
	ch := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, pw, err := p.EnsureUser(ctx, "concurrent@example.com", "conc-node", "waypoint_test", nil)
			ch <- result{pw, err}
		}()
	}

	var passwords []string
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err != nil {
			t.Fatalf("concurrent EnsureUser failed: %v", r.err)
		}
		passwords = append(passwords, r.password)
	}

	// At least one of the two passwords should work (the last one written wins).
	var working int
	for _, pw := range passwords {
		connStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, pw, backend)
		conn, err := pgx.Connect(ctx, connStr)
		if err == nil {
			conn.Close(ctx)
			working++
		}
	}
	if working == 0 {
		t.Fatal("neither password works after concurrent rotation")
	}
}

func TestIntegration_EnsureUser_MissingDatabase(t *testing.T) {
	p := setupProvisioner(t)
	ctx := context.Background()

	// Request a database that doesn't exist. GRANT CONNECT should fail
	// gracefully (logged warning), but the role should still be created.
	pgUser, password, err := p.EnsureUser(ctx, "missingdb@example.com", "missingdb-node", "nonexistent_db", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn := adminConn(t)
		c := context.Background()
		s := pgx.Identifier{pgUser}.Sanitize()
		conn.Exec(c, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", s))
		conn.Exec(c, fmt.Sprintf("DROP OWNED BY %s", s))
		conn.Exec(c, fmt.Sprintf("DROP ROLE IF EXISTS %s", s))
	})

	// Role should exist despite the GRANT CONNECT failure.
	conn := adminConn(t)
	var exists bool
	err = conn.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", pgUser).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("role %q should exist even though database doesn't exist", pgUser)
	}

	// Password should have been set.
	if password == "" {
		t.Fatal("expected non-empty password")
	}
}

func TestIntegration_EnsureUser_PermissionGrantFailure(t *testing.T) {
	p := setupProvisioner(t)
	ctx := context.Background()
	_, backend := testutil.PostgresBackend(t)

	// Pass an invalid permission that will fail to GRANT.
	badPerms := &auth.DBPermissions{Permissions: []string{"USAGE ON SCHEMA nonexistent_schema"}}
	pgUser, password, err := p.EnsureUser(ctx, "badperm@example.com", "badperm-node", "waypoint_test", badPerms)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn := adminConn(t)
		c := context.Background()
		s := pgx.Identifier{pgUser}.Sanitize()
		conn.Exec(c, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", s))
		conn.Exec(c, fmt.Sprintf("DROP OWNED BY %s", s))
		conn.Exec(c, fmt.Sprintf("DROP ROLE IF EXISTS %s", s))
	})

	// Role should still be usable despite permission grant failure.
	userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, backend)
	userConn, err := pgx.Connect(ctx, userConnStr)
	if err != nil {
		t.Fatalf("login should work despite permission failure: %v", err)
	}
	defer userConn.Close(ctx)

	var currentUser string
	if err := userConn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser); err != nil {
		t.Fatal(err)
	}
	if currentUser != pgUser {
		t.Fatalf("expected current_user=%q, got %q", pgUser, currentUser)
	}
}

func TestIntegration_EnsureUser_SQLStatements(t *testing.T) {
	p := setupProvisioner(t)
	ctx := context.Background()

	// Create a table to grant on.
	conn := adminConn(t)
	_, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.sql_test_table (id int)")
	if err != nil {
		t.Fatalf("create test table: %v", err)
	}
	t.Cleanup(func() {
		conn := adminConn(t)
		conn.Exec(context.Background(), "DROP TABLE IF EXISTS public.sql_test_table")
	})

	perms := &auth.DBPermissions{
		SQL: []string{
			"GRANT SELECT ON public.sql_test_table TO {role}",
		},
	}
	pgUser, password, err := p.EnsureUser(ctx, "sqltest@example.com", "sql-node", "waypoint_test", perms)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupRole(t, pgUser) })

	// Connect as the provisioned user and verify access.
	_, backend := testutil.PostgresBackend(t)
	userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, backend)
	userConn, err := pgx.Connect(ctx, userConnStr)
	if err != nil {
		t.Fatalf("login as provisioned user failed: %v", err)
	}
	defer userConn.Close(ctx)

	// The SQL statement should have granted SELECT on the test table.
	_, err = userConn.Exec(ctx, "SELECT * FROM public.sql_test_table")
	if err != nil {
		t.Fatalf("SELECT should succeed after SQL grant: %v", err)
	}
}

// cleanupRole is a test helper that drops a provisioned role for test isolation.
func cleanupRole(t *testing.T, pgUser string) {
	t.Helper()
	conn := adminConn(t)
	ctx := context.Background()
	sanitized := pgx.Identifier{pgUser}.Sanitize()
	conn.Exec(ctx, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", sanitized))
	conn.Exec(ctx, fmt.Sprintf("DROP OWNED BY %s", sanitized))
	conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", sanitized))
}

// Ensure the redis import is used (it's needed for the RedisClient call via testutil).
var _ *redis.Client
