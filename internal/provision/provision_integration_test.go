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
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

// dbBackend describes a database backend for parameterized tests.
type dbBackend struct {
	name      string
	connStr   string
	backend   string
	adminUser string
	adminPass string
}

func testBackends(t *testing.T) []dbBackend {
	t.Helper()
	backends := make([]dbBackend, 0, 2)

	pgConnStr, pgBackend := testutil.PostgresBackend(t)
	backends = append(backends, dbBackend{name: "postgres", connStr: pgConnStr, backend: pgBackend, adminUser: "admin", adminPass: "adminpass"})

	crdbConnStr, crdbBackend := testutil.CockroachDBBackend(t)
	backends = append(backends, dbBackend{name: "cockroachdb", connStr: crdbConnStr, backend: crdbBackend, adminUser: "wpadmin", adminPass: "adminpass"})

	return backends
}

func setupProvisionerFor(t *testing.T, db dbBackend) *Provisioner {
	t.Helper()
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewProvisioner(db.adminUser, db.adminPass, "waypoint_test", db.backend, "wp_", store, logger)
}

func adminConnFor(t *testing.T, db dbBackend) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), db.connStr)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// roleExistsFor checks role existence using the appropriate query for the dialect.
func roleExistsFor(t *testing.T, db dbBackend, rolname string) bool {
	t.Helper()
	conn := adminConnFor(t, db)

	// Detect dialect from the connection.
	var version string
	if err := conn.QueryRow(context.Background(), "SELECT version()").Scan(&version); err != nil {
		t.Fatalf("get version: %v", err)
	}
	var query string
	if db.name == "cockroachdb" {
		query = "SELECT EXISTS(SELECT 1 FROM system.users WHERE username = $1)"
	} else {
		query = "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)"
	}

	var exists bool
	if err := conn.QueryRow(context.Background(), query, rolname).Scan(&exists); err != nil {
		t.Fatalf("check role exists: %v", err)
	}
	return exists
}

func cleanupRoleFor(t *testing.T, db dbBackend, pgUser string) {
	t.Helper()
	conn := adminConnFor(t, db)
	ctx := context.Background()
	sanitized := pgx.Identifier{pgUser}.Sanitize()
	conn.Exec(ctx, fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", sanitized))
	conn.Exec(ctx, fmt.Sprintf("DROP OWNED BY %s", sanitized))
	conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", sanitized))
}

func TestIntegration_EnsureUser_CreatesRole(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, _, err := p.EnsureUser(ctx, "alice@example.com", "alice-laptop", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			if !roleExistsFor(t, db, pgUser) {
				t.Fatalf("role %q should exist", pgUser)
			}
		})
	}
}

func TestIntegration_EnsureUser_CanLogin(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, password, err := p.EnsureUser(ctx, "bob@example.com", "bob-desktop", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, db.backend)
			userConn, err := pgx.Connect(ctx, userConnStr)
			if err != nil {
				t.Fatalf("login as provisioned user failed: %v", err)
			}
			defer userConn.Close(ctx)

			var currentUser string
			if err := userConn.QueryRow(ctx, "SELECT current_user").Scan(&currentUser); err != nil {
				t.Fatal(err)
			}
			if currentUser != pgUser {
				t.Fatalf("expected current_user=%q, got %q", pgUser, currentUser)
			}
		})
	}
}

func TestIntegration_EnsureUser_UpdatesPassword(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, password1, err := p.EnsureUser(ctx, "carol@example.com", "carol-laptop", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			_, password2, err := p.EnsureUser(ctx, "carol@example.com", "carol-laptop", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}

			if password1 == password2 {
				t.Fatal("expected different passwords on second EnsureUser call")
			}

			oldConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password1, db.backend)
			_, err = pgx.Connect(ctx, oldConnStr)
			if err == nil {
				t.Fatal("old password should not work after rotation")
			}

			newConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password2, db.backend)
			conn, err := pgx.Connect(ctx, newConnStr)
			if err != nil {
				t.Fatalf("new password should work: %v", err)
			}
			conn.Close(ctx)
		})
	}
}

func TestIntegration_EnsureUser_GrantConnect(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, _, err := p.EnsureUser(ctx, "dave@example.com", "dave-node", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			conn := adminConnFor(t, db)
			var hasConnect bool
			err = conn.QueryRow(ctx,
				"SELECT has_database_privilege($1, 'waypoint_test', 'CONNECT')", pgUser).Scan(&hasConnect)
			if err != nil {
				t.Fatal(err)
			}
			if !hasConnect {
				t.Fatalf("role %q should have CONNECT on waypoint_test", pgUser)
			}
		})
	}
}

func TestIntegration_EnsureUser_ConcurrentPasswordRotation(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, _, err := p.EnsureUser(ctx, "concurrent@example.com", "conc-node", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

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

			var working int
			for _, pw := range passwords {
				connStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, pw, db.backend)
				conn, err := pgx.Connect(ctx, connStr)
				if err == nil {
					conn.Close(ctx)
					working++
				}
			}
			if working == 0 {
				t.Fatal("neither password works after concurrent rotation")
			}
		})
	}
}

func TestIntegration_EnsureUser_MissingDatabase(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, password, err := p.EnsureUser(ctx, "missingdb@example.com", "missingdb-node", "nonexistent_db", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			if !roleExistsFor(t, db, pgUser) {
				t.Fatalf("role %q should exist even though database doesn't exist", pgUser)
			}

			if password == "" {
				t.Fatal("expected non-empty password")
			}
		})
	}
}

func TestIntegration_EnsureUser_PermissionGrantFailure(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			badPerms := &auth.DBPermissions{Permissions: []string{"USAGE ON SCHEMA nonexistent_schema"}}
			pgUser, password, err := p.EnsureUser(ctx, "badperm@example.com", "badperm-node", "waypoint_test", badPerms)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, db.backend)
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
		})
	}
}

func TestIntegration_EnsureUser_SQLStatements(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			conn := adminConnFor(t, db)
			_, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.sql_test_table (id int)")
			if err != nil {
				t.Fatalf("create test table: %v", err)
			}
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.sql_test_table")
			})

			perms := &auth.DBPermissions{
				SQL: []string{
					"GRANT SELECT ON public.sql_test_table TO {{.Role}}",
				},
			}
			pgUser, password, err := p.EnsureUser(ctx, "sqltest@example.com", "sql-node", "waypoint_test", perms)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, db.backend)
			userConn, err := pgx.Connect(ctx, userConnStr)
			if err != nil {
				t.Fatalf("login as provisioned user failed: %v", err)
			}
			defer userConn.Close(ctx)

			_, err = userConn.Exec(ctx, "SELECT * FROM public.sql_test_table")
			if err != nil {
				t.Fatalf("SELECT should succeed after SQL grant: %v", err)
			}
		})
	}
}

// Ensure the redis import is used (it's needed for the RedisClient call via testutil).
var _ *redis.Client
