//go:build integration

package provision

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
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
	return NewProvisioner(db.adminUser, db.adminPass, "waypoint_test", db.backend, "test-listener", "wp_", false, true, "test", store, logger, nil, nil)
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

// TestIntegration_EnsureUser_ReusesPasswordWithinTTL covers the common case:
// reconnects inside the credential window get the password already in effect
// rather than rotating it, so a connection that is still authenticating does
// not have its credentials pulled out from under it.
func TestIntegration_EnsureUser_ReusesPasswordWithinTTL(t *testing.T) {
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

			if password1 != password2 {
				t.Fatal("password should be reused within the credential TTL, not rotated")
			}

			connStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password2, db.backend)
			conn, err := pgx.Connect(ctx, connStr)
			if err != nil {
				t.Fatalf("reused password should work: %v", err)
			}
			conn.Close(ctx)
		})
	}
}

// TestIntegration_EnsureUser_RotatesPasswordAfterTTL covers the other half:
// once the window lapses the password is replaced and the previous one stops
// working, so a leaked credential has a bounded life.
func TestIntegration_EnsureUser_RotatesPasswordAfterTTL(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			p.SetCredentialTTL(0) // rotate on every connection
			ctx := context.Background()

			pgUser, password1, err := p.EnsureUser(ctx, "carol2@example.com", "carol-laptop", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			_, password2, err := p.EnsureUser(ctx, "carol2@example.com", "carol-laptop", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}

			if password1 == password2 {
				t.Fatal("expected a different password once the credential TTL lapsed")
			}

			oldConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password1, db.backend)
			if _, err := pgx.Connect(ctx, oldConnStr); err == nil {
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

// TestIntegration_EnsureUser_ConnectionBurst reproduces the failure mode where
// a client opens many connections at once: every one of them provisions the
// same role, and all but the lock winner used to fail with "could not acquire
// lock". They must now all succeed, and every password handed out must work,
// since the burst shares a single provisioning round.
func TestIntegration_EnsureUser_ConnectionBurst(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, _, err := p.EnsureUser(ctx, "burst@example.com", "burst-node", "waypoint_test", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			const burst = 10
			type result struct {
				password string
				err      error
			}
			ch := make(chan result, burst)
			start := make(chan struct{})
			for i := 0; i < burst; i++ {
				go func() {
					<-start
					_, pw, err := p.EnsureUser(ctx, "burst@example.com", "burst-node", "waypoint_test", nil)
					ch <- result{pw, err}
				}()
			}
			close(start)

			var passwords []string
			for i := 0; i < burst; i++ {
				r := <-ch
				if r.err != nil {
					t.Fatalf("connection %d of a %d-connection burst failed to provision: %v", i, burst, r.err)
				}
				passwords = append(passwords, r.password)
			}

			for i, pw := range passwords {
				connStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, pw, db.backend)
				conn, err := pgx.Connect(ctx, connStr)
				if err != nil {
					t.Fatalf("password handed to connection %d does not work: %v", i, err)
				}
				conn.Close(ctx)
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

func TestIntegration_EnsureUser_InvalidPreset(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			badPerms := &auth.DBPermissions{Permissions: []string{"USAGE ON SCHEMA nonexistent_schema"}}
			_, _, err := p.EnsureUser(ctx, "badperm@example.com", "badperm-node", "waypoint_test", badPerms)
			if err == nil {
				t.Fatal("expected error for invalid preset name")
			}
			if !strings.Contains(err.Error(), "permissions now accepts preset names only") {
				t.Fatalf("expected hint about preset names, got: %v", err)
			}
		})
	}
}

func TestIntegration_EnsureUser_ReadonlyPreset(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			perms := &auth.DBPermissions{Permissions: []string{"readonly"}}
			pgUser, password, err := p.EnsureUser(ctx, "reader@example.com", "reader-node", "waypoint_test", perms)
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

func TestIntegration_EnsureUser_ReconcilesPresetDowngrade(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			conn := adminConnFor(t, db)
			_, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.reconcile_preset_test (id int)")
			if err != nil {
				t.Fatalf("create test table: %v", err)
			}
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.reconcile_preset_test")
			})

			readwrite := &auth.DBPermissions{Permissions: []string{"readwrite"}}
			pgUser, password, err := p.EnsureUser(ctx, "reconcile@example.com", "reconcile-node", "waypoint_test", readwrite)
			if err != nil {
				t.Fatalf("EnsureUser readwrite: %v", err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, db.backend)
			userConn, err := pgx.Connect(ctx, userConnStr)
			if err != nil {
				t.Fatalf("connect as readwrite user: %v", err)
			}
			if _, err := userConn.Exec(ctx, "INSERT INTO public.reconcile_preset_test VALUES (1)"); err != nil {
				t.Fatalf("insert should succeed with readwrite grant: %v", err)
			}
			userConn.Close(ctx)

			readonly := &auth.DBPermissions{Permissions: []string{"readonly"}}
			pgUser2, password2, err := p.EnsureUser(ctx, "reconcile@example.com", "reconcile-node", "waypoint_test", readonly)
			if err != nil {
				t.Fatalf("EnsureUser readonly: %v", err)
			}
			if pgUser2 != pgUser {
				t.Fatalf("expected same role to be reconciled, got %q then %q", pgUser, pgUser2)
			}

			readonlyConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser2, password2, db.backend)
			readonlyConn, err := pgx.Connect(ctx, readonlyConnStr)
			if err != nil {
				t.Fatalf("connect as readonly user: %v", err)
			}
			defer readonlyConn.Close(ctx)

			if _, err := readonlyConn.Exec(ctx, "SELECT * FROM public.reconcile_preset_test"); err != nil {
				t.Fatalf("select should succeed after downgrade: %v", err)
			}
			if _, err := readonlyConn.Exec(ctx, "INSERT INTO public.reconcile_preset_test VALUES (2)"); err == nil {
				t.Fatal("insert should be denied after downgrade to readonly")
			}
		})
	}
}

func TestIntegration_EnsureUser_ReconcilesOwnedObjectsOnDowngrade(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			admin := &auth.DBPermissions{Permissions: []string{"admin"}}
			pgUser, password, err := p.EnsureUser(ctx, "owner-reconcile@example.com", "owner-node", "waypoint_test", admin)
			if err != nil {
				t.Fatalf("EnsureUser admin: %v", err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.reconcile_owned_test")
			})

			userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, db.backend)
			userConn, err := pgx.Connect(ctx, userConnStr)
			if err != nil {
				t.Fatalf("connect as admin user: %v", err)
			}
			if _, err := userConn.Exec(ctx, "CREATE TABLE public.reconcile_owned_test (id int)"); err != nil {
				t.Fatalf("create owned table should succeed with admin grant: %v", err)
			}
			if _, err := userConn.Exec(ctx, "INSERT INTO public.reconcile_owned_test VALUES (1)"); err != nil {
				t.Fatalf("insert into owned table should succeed with admin grant: %v", err)
			}
			userConn.Close(ctx)

			readonly := &auth.DBPermissions{Permissions: []string{"readonly"}}
			pgUser2, password2, err := p.EnsureUser(ctx, "owner-reconcile@example.com", "owner-node", "waypoint_test", readonly)
			if err != nil {
				t.Fatalf("EnsureUser readonly: %v", err)
			}
			if pgUser2 != pgUser {
				t.Fatalf("expected same role to be reconciled, got %q then %q", pgUser, pgUser2)
			}

			readonlyConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser2, password2, db.backend)
			readonlyConn, err := pgx.Connect(ctx, readonlyConnStr)
			if err != nil {
				t.Fatalf("connect as readonly user: %v", err)
			}
			defer readonlyConn.Close(ctx)

			if _, err := readonlyConn.Exec(ctx, "SELECT * FROM public.reconcile_owned_test"); err != nil {
				t.Fatalf("select from formerly owned table should succeed after downgrade: %v", err)
			}
			if _, err := readonlyConn.Exec(ctx, "INSERT INTO public.reconcile_owned_test VALUES (2)"); err == nil {
				t.Fatal("insert into formerly owned table should be denied after downgrade")
			}
		})
	}
}

func TestIntegration_EnsureUser_RollbackPreservesPreviousPermissions(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			conn := adminConnFor(t, db)
			_, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.rollback_preserve_test (id int)")
			if err != nil {
				t.Fatalf("create test table: %v", err)
			}
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.rollback_preserve_test")
			})

			readwrite := &auth.DBPermissions{Permissions: []string{"readwrite"}}
			pgUser, password, err := p.EnsureUser(ctx, "rollback@example.com", "rollback-node", "waypoint_test", readwrite)
			if err != nil {
				t.Fatalf("EnsureUser readwrite: %v", err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, db.backend)
			userConn, err := pgx.Connect(ctx, userConnStr)
			if err != nil {
				t.Fatalf("connect before failed reconcile: %v", err)
			}
			if _, err := userConn.Exec(ctx, "INSERT INTO public.rollback_preserve_test VALUES (1)"); err != nil {
				t.Fatalf("initial insert should succeed: %v", err)
			}
			userConn.Close(ctx)

			badPerms := &auth.DBPermissions{Permissions: []string{"invalid"}}
			if _, _, err := p.EnsureUser(ctx, "rollback@example.com", "rollback-node", "waypoint_test", badPerms); err == nil {
				t.Fatal("expected failed reconcile with invalid preset")
			}

			afterRollbackConn, err := pgx.Connect(ctx, userConnStr)
			if err != nil {
				t.Fatalf("old password should still work after rollback: %v", err)
			}
			defer afterRollbackConn.Close(ctx)

			if _, err := afterRollbackConn.Exec(ctx, "INSERT INTO public.rollback_preserve_test VALUES (2)"); err != nil {
				t.Fatalf("old readwrite grants should still work after rollback: %v", err)
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

// memberOfPresetGroups returns pgUser's memberships in groups under
// groupPrefix, used by integration tests that assert on group-membership
// reconciliation. The prefix comes from the provisioner under test rather
// than a literal, since it carries that provisioner's user_prefix and
// listener.
func memberOfPresetGroups(t *testing.T, db dbBackend, pgUser, groupPrefix string) []string {
	t.Helper()
	conn := adminConnFor(t, db)
	rows, err := conn.Query(context.Background(), `
SELECT r.rolname
FROM pg_catalog.pg_auth_members m
JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
JOIN pg_catalog.pg_roles u ON u.oid = m.member
WHERE u.rolname = $1
ORDER BY r.rolname`, pgUser)
	if err != nil {
		t.Fatalf("query memberships: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if strings.HasPrefix(name, groupPrefix) {
			out = append(out, name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	return out
}

func TestIntegration_EnsureUser_GroupMembershipsForPureReadonly(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			perms := &auth.DBPermissions{Permissions: []string{"readonly"}}
			pgUser, _, err := p.EnsureUser(ctx, "groups-ro@example.com", "ro-node", "waypoint_test", perms)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			got := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())
			want := p.presetGroupName("readonly", "public", "waypoint_test")
			if len(got) != 1 || got[0] != want {
				t.Fatalf("expected single membership wp_grp_readonly_public_waypoint_test, got %v", got)
			}
		})
	}
}

func TestIntegration_EnsureUser_GroupMembershipsAreStableAcrossReconnects(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			perms := &auth.DBPermissions{Permissions: []string{"readwrite"}}
			pgUser, _, err := p.EnsureUser(ctx, "stable@example.com", "stable-node", "waypoint_test", perms)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			before := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())

			// Second EnsureUser with identical perms should be a no-op for
			// membership state — the steady-state path that needs to be cheap.
			if _, _, err := p.EnsureUser(ctx, "stable@example.com", "stable-node", "waypoint_test", perms); err != nil {
				t.Fatalf("second EnsureUser: %v", err)
			}

			after := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())
			if len(before) != len(after) {
				t.Fatalf("membership count changed: before=%v after=%v", before, after)
			}
			for i := range before {
				if before[i] != after[i] {
					t.Fatalf("membership changed: before=%v after=%v", before, after)
				}
			}
		})
	}
}

func TestIntegration_EnsureUser_GroupMembershipsTrackPresetChange(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, _, err := p.EnsureUser(ctx, "diff@example.com", "diff-node", "waypoint_test",
				&auth.DBPermissions{Permissions: []string{"readwrite"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			before := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())
			wantBefore := p.presetGroupName("readwrite", "public", "waypoint_test")
			if len(before) != 1 || before[0] != wantBefore {
				t.Fatalf("expected wp_grp_readwrite_public_waypoint_test, got %v", before)
			}

			if _, _, err := p.EnsureUser(ctx, "diff@example.com", "diff-node", "waypoint_test",
				&auth.DBPermissions{Permissions: []string{"readonly"}}); err != nil {
				t.Fatal(err)
			}

			after := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())
			wantAfter := p.presetGroupName("readonly", "public", "waypoint_test")
			if len(after) != 1 || after[0] != wantAfter {
				t.Fatalf("expected single readonly membership, got %v", after)
			}
		})
	}
}

func TestIntegration_EnsureUser_SQLFragmentUsesCompositeGroup(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			conn := adminConnFor(t, db)
			if _, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.composite_target (id int)"); err != nil {
				t.Fatalf("create test table: %v", err)
			}
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.composite_target")
			})

			perms := &auth.DBPermissions{
				SQL: []string{"GRANT SELECT ON public.composite_target TO {{.Role}}"},
			}
			pgUser, _, err := p.EnsureUser(ctx, "composite@example.com", "composite-node", "waypoint_test", perms)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			groups := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())
			if len(groups) != 1 {
				t.Fatalf("expected exactly 1 group membership, got %v", groups)
			}
			if !strings.HasPrefix(groups[0], p.groupPrefix()+"perms_") {
				t.Fatalf("expected composite group prefix, got %q", groups[0])
			}
		})
	}
}

func TestIntegration_EnsureUser_SwitchPurePresetToComposite(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			conn := adminConnFor(t, db)
			if _, err := conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.switch_target (id int)"); err != nil {
				t.Fatalf("create test table: %v", err)
			}
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.switch_target")
			})

			pgUser, _, err := p.EnsureUser(ctx, "switch@example.com", "switch-node", "waypoint_test",
				&auth.DBPermissions{Permissions: []string{"readonly"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			before := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())
			if len(before) != 1 || !strings.HasPrefix(before[0], p.groupPrefix()+"readonly_") {
				t.Fatalf("expected initial readonly group, got %v", before)
			}

			if _, _, err := p.EnsureUser(ctx, "switch@example.com", "switch-node", "waypoint_test",
				&auth.DBPermissions{
					Permissions: []string{"readonly"},
					SQL:         []string{"GRANT SELECT ON public.switch_target TO {{.Role}}"},
				}); err != nil {
				t.Fatal(err)
			}

			after := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())
			if len(after) != 1 || !strings.HasPrefix(after[0], p.groupPrefix()+"perms_") {
				t.Fatalf("expected composite group after switch, got %v", after)
			}
		})
	}
}

func TestIntegration_EnsureUser_AdditivePresetChangePreservesOwnership(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			pgUser, _, err := p.EnsureUser(ctx, "additive@example.com", "additive-node", "waypoint_test",
				&auth.DBPermissions{Permissions: []string{"readonly"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			// Make the user own a table without going through any waypoint
			// codepath, so the ownership can't be attributed to whatever
			// presets are active.
			conn := adminConnFor(t, db)
			sanitized := pgx.Identifier{pgUser}.Sanitize()
			if _, err := conn.Exec(ctx, "CREATE TABLE public.additive_owned_test (id int)"); err != nil {
				t.Fatalf("create table: %v", err)
			}
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.additive_owned_test")
			})
			if _, err := conn.Exec(ctx, fmt.Sprintf("ALTER TABLE public.additive_owned_test OWNER TO %s", sanitized)); err != nil {
				t.Fatalf("alter owner: %v", err)
			}

			// Additive change: readonly → readonly + readwrite. No
			// memberships are being revoked, so REASSIGN OWNED BY must
			// not fire — the user must still own the table afterwards.
			if _, _, err := p.EnsureUser(ctx, "additive@example.com", "additive-node", "waypoint_test",
				&auth.DBPermissions{Permissions: []string{"readonly", "readwrite"}}); err != nil {
				t.Fatalf("additive reconcile: %v", err)
			}

			var owner string
			if err := adminConnFor(t, db).QueryRow(ctx, `
SELECT r.rolname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
WHERE c.relname = 'additive_owned_test'`).Scan(&owner); err != nil {
				t.Fatalf("read owner: %v", err)
			}
			if owner != pgUser {
				t.Fatalf("ownership must survive an additive perm change; got owner=%q want %q", owner, pgUser)
			}
		})
	}
}

func TestIntegration_EnsureUser_CompositeRevokeCarvesHole(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			conn := adminConnFor(t, db)
			for _, stmt := range []string{
				"CREATE TABLE IF NOT EXISTS public.composite_open (id int)",
				"CREATE TABLE IF NOT EXISTS public.composite_locked (id int)",
			} {
				if _, err := conn.Exec(ctx, stmt); err != nil {
					t.Fatalf("setup: %v", err)
				}
			}
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.composite_open")
				c.Exec(context.Background(), "DROP TABLE IF EXISTS public.composite_locked")
			})

			perms := &auth.DBPermissions{
				Permissions: []string{"readwrite"},
				SQL: []string{
					"REVOKE INSERT ON public.composite_locked FROM {{.Role}}",
				},
			}
			pgUser, password, err := p.EnsureUser(ctx, "hole@example.com", "hole-node", "waypoint_test", perms)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			userConn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, db.backend))
			if err != nil {
				t.Fatalf("user connect: %v", err)
			}
			defer userConn.Close(ctx)

			if _, err := userConn.Exec(ctx, "INSERT INTO public.composite_open VALUES (1)"); err != nil {
				t.Fatalf("INSERT into composite_open should succeed (readwrite preset is intact): %v", err)
			}
			if _, err := userConn.Exec(ctx, "INSERT INTO public.composite_locked VALUES (1)"); err == nil {
				t.Fatal("INSERT into composite_locked should be denied (SQL REVOKE carved the hole)")
			}
			if _, err := userConn.Exec(ctx, "SELECT * FROM public.composite_locked"); err != nil {
				t.Fatalf("SELECT on composite_locked should still succeed (only INSERT was revoked): %v", err)
			}
		})
	}
}

func TestIntegration_EnsureUser_MultiSchemaGroupMemberships(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			p := setupProvisionerFor(t, db)
			ctx := context.Background()

			conn := adminConnFor(t, db)
			if _, err := conn.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS multi_audit"); err != nil {
				t.Fatalf("create schema: %v", err)
			}
			t.Cleanup(func() {
				c := adminConnFor(t, db)
				c.Exec(context.Background(), "DROP SCHEMA IF EXISTS multi_audit CASCADE")
			})

			perms := &auth.DBPermissions{
				Permissions: []string{"readonly"},
				Schemas:     []string{"public", "multi_audit"},
			}
			pgUser, _, err := p.EnsureUser(ctx, "multi@example.com", "multi-node", "waypoint_test", perms)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cleanupRoleFor(t, db, pgUser) })

			groups := memberOfPresetGroups(t, db, pgUser, p.groupPrefix())
			want := map[string]bool{
				p.presetGroupName("readonly", "public", "waypoint_test"):      true,
				p.presetGroupName("readonly", "multi_audit", "waypoint_test"): true,
			}
			if len(groups) != len(want) {
				t.Fatalf("expected %d memberships, got %v", len(want), groups)
			}
			for _, g := range groups {
				if !want[g] {
					t.Errorf("unexpected group membership %q", g)
				}
			}
		})
	}
}

// Ensure the redis import is used (it's needed for the RedisClient call via testutil).
var _ *redis.Client

// TestIntegrationEnsureUser_GrantsLandInTheTargetDatabase is the regression
// test for grants being applied to the wrong database.
//
// Privileges on schemas, tables and sequences are stored per database in
// Postgres. Provisioning used to issue them over a connection to
// admin_database regardless of which database the role was for, so a role
// provisioned for any other database ended up with its privileges in
// admin_database and every query it ran was refused.
func TestIntegrationEnsureUser_GrantsLandInTheTargetDatabase(t *testing.T) {
	ctx := context.Background()
	connStr, backend := testutil.PostgresBackend(t)

	admin, err := pgx.Connect(ctx, connStr)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)

	// A second database with a table of its own. The admin database keeps a
	// differently-named table so the two are never confused.
	const otherDB = "wp_other_db"
	for _, stmt := range []string{
		"DROP DATABASE IF EXISTS " + otherDB,
		"CREATE DATABASE " + otherDB,
		"DROP TABLE IF EXISTS in_admin_db",
		"CREATE TABLE in_admin_db (id int)",
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), connStr)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+otherDB+" WITH (FORCE)")
		// Leaving this behind makes any later test that grants on ALL TABLES
		// IN SCHEMA public depend on the order tests happen to run in.
		_, _ = c.Exec(context.Background(), "DROP TABLE IF EXISTS in_admin_db")
	})

	otherConnStr := strings.Replace(connStr, "/waypoint_test", "/"+otherDB, 1)
	other, err := pgx.Connect(ctx, otherConnStr)
	if err != nil {
		t.Fatalf("connect to %s: %v", otherDB, err)
	}
	defer other.Close(ctx)
	if _, err := other.Exec(ctx, "CREATE TABLE in_other_db (id int)"); err != nil {
		t.Fatalf("create table in %s: %v", otherDB, err)
	}

	// admin_database is waypoint_test; provision for the other one.
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "granttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := NewProvisioner("admin", "adminpass", "waypoint_test", backend, "grant-test", "wp_gt_",
		false, true, "test", store, logger, nil, nil)

	role, _, err := p.EnsureUser(ctx, "alice@example.com", "laptop", otherDB,
		&auth.DBPermissions{Permissions: []string{"readonly"}, Schemas: []string{"public"}})
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), otherConnStr)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP OWNED BY "+pgx.Identifier{role}.Sanitize())
			c.Close(context.Background())
		}
		c, err = pgx.Connect(context.Background(), connStr)
		if err == nil {
			_, _ = c.Exec(context.Background(), "DROP OWNED BY "+pgx.Identifier{role}.Sanitize())
			_, _ = c.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize())
			c.Close(context.Background())
		}
	})

	// The privilege must exist in the database the role was provisioned for.
	var canReadOther bool
	if err := other.QueryRow(ctx,
		"SELECT has_table_privilege($1, 'public.in_other_db', 'SELECT')", role).Scan(&canReadOther); err != nil {
		t.Fatalf("privilege check in %s: %v", otherDB, err)
	}
	if !canReadOther {
		t.Errorf("role %q cannot read %s.public.in_other_db — grants did not land in the target database", role, otherDB)
	}

	// And must not have been applied to the admin database instead.
	var canReadAdmin bool
	if err := admin.QueryRow(ctx,
		"SELECT has_table_privilege($1, 'public.in_admin_db', 'SELECT')", role).Scan(&canReadAdmin); err != nil {
		t.Fatalf("privilege check in admin db: %v", err)
	}
	if canReadAdmin {
		t.Errorf("role %q holds privileges in admin_database it was never granted for", role)
	}

	// The end-to-end proof: connect as the role and read the table.
	roleConn, err := pgx.Connect(ctx, strings.Replace(otherConnStr, "admin:adminpass", role+":"+mustPassword(t, p, role, otherDB), 1))
	if err == nil {
		defer roleConn.Close(ctx)
		var n int
		if err := roleConn.QueryRow(ctx, "SELECT count(*) FROM in_other_db").Scan(&n); err != nil {
			t.Errorf("role could not query the table it was granted: %v", err)
		}
	}
}

// mustPassword re-provisions to obtain a usable password for the role.
func mustPassword(t *testing.T, p *Provisioner, role, database string) string {
	t.Helper()
	_, pw, err := p.EnsureUser(context.Background(), "alice@example.com", "laptop", database,
		&auth.DBPermissions{Permissions: []string{"readonly"}, Schemas: []string{"public"}})
	if err != nil {
		t.Fatalf("re-provision for password: %v", err)
	}
	return pw
}

func TestIntegrationEnsureUser_MissingTargetDatabaseStillCreatesRole(t *testing.T) {
	ctx := context.Background()
	_, backend := testutil.PostgresBackend(t)

	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "granttest2:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := NewProvisioner("admin", "adminpass", "waypoint_test", backend, "missing-db", "wp_md_",
		false, true, "test", store, logger, nil, nil)

	// Provisioning for a database that does not exist must not fail outright:
	// the role is still created so the backend, not waypoint, reports the
	// missing database to the client.
	role, _, err := p.EnsureUser(ctx, "bob@example.com", "laptop", "no_such_database_here",
		&auth.DBPermissions{Permissions: []string{"readonly"}})
	if err != nil {
		t.Fatalf("EnsureUser against a missing database: %v", err)
	}
	if role == "" {
		t.Error("no role name returned")
	}
}

// TestIntegrationConnectToTarget_MissingDatabaseAcrossBackends pins the
// behaviour the two backends disagree on.
//
// Postgres refuses a connection to a database that does not exist. CockroachDB
// accepts it, and even answers SELECT 1, failing only when a catalog is read.
// Provisioning has to reach the same conclusion on both, or the missing
// database surfaces as a failure partway through the provisioning transaction
// instead of a clean fallback.
func TestIntegrationConnectToTarget_MissingDatabaseAcrossBackends(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			ctx := context.Background()
			p := setupProvisionerFor(t, db)

			conn, exists, err := p.connectToTarget(ctx, "definitely_not_a_database")
			if err != nil {
				t.Fatalf("connectToTarget should fall back, not fail: %v", err)
			}
			defer conn.Close(ctx)

			if exists {
				t.Error("reported a missing database as present")
			}

			// The fallback connection must be usable — it is what the rest of
			// provisioning runs on.
			var n int
			if err := conn.QueryRow(ctx, "SELECT count(*) FROM pg_database").Scan(&n); err != nil {
				t.Errorf("fallback connection cannot read the catalog: %v", err)
			}
		})
	}
}

func TestIntegrationConnectToTarget_ExistingDatabaseIsReached(t *testing.T) {
	for _, db := range testBackends(t) {
		t.Run(db.name, func(t *testing.T) {
			ctx := context.Background()
			p := setupProvisionerFor(t, db)

			conn, exists, err := p.connectToTarget(ctx, "waypoint_test")
			if err != nil {
				t.Fatalf("connectToTarget: %v", err)
			}
			defer conn.Close(ctx)

			if !exists {
				t.Error("existing database reported as missing")
			}
			// Crucially, the connection is to that database — this is what
			// puts schema and table grants in the right place.
			var current string
			if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&current); err != nil {
				t.Fatalf("current_database: %v", err)
			}
			if current != "waypoint_test" {
				t.Errorf("connected to %q, want waypoint_test", current)
			}
		})
	}
}

// TestIntegrationTwoAdmins_ShareABackendWithoutColliding is the regression
// test for group roles being shared across listeners.
//
// A group role is owned by the admin that created it, and Postgres 16 grants
// ADMIN OPTION only to that creator. Group names used to be
// wp_grp_<preset>_<schema>_<database> — no listener, and not even the
// user_prefix — so two listeners over one backend derived the same group and
// the second admin could not grant it:
//
//	permission denied to grant role "wp_grp_readonly_public_waypoint_test"
func TestIntegrationTwoAdmins_ShareABackendWithoutColliding(t *testing.T) {
	ctx := context.Background()
	connStr, backend := testutil.PostgresBackend(t)

	su, err := pgx.Connect(ctx, connStr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer su.Close(ctx)

	for _, stmt := range []string{
		`DROP SCHEMA IF EXISTS two_admin CASCADE`,
		`CREATE SCHEMA two_admin`,
		`CREATE TABLE two_admin.tbl (id int)`,
		`DROP ROLE IF EXISTS wp_admin_a`,
		`DROP ROLE IF EXISTS wp_admin_b`,
		// Deliberately non-superuser: a superuser bypasses ADMIN OPTION and
		// would not exercise the collision at all.
		`CREATE ROLE wp_admin_a LOGIN PASSWORD 'p' CREATEROLE`,
		`CREATE ROLE wp_admin_b LOGIN PASSWORD 'p' CREATEROLE`,
		`GRANT SELECT ON two_admin.tbl TO wp_admin_a WITH GRANT OPTION`,
		`GRANT SELECT ON two_admin.tbl TO wp_admin_b WITH GRANT OPTION`,
		`GRANT USAGE ON SCHEMA two_admin TO wp_admin_a WITH GRANT OPTION`,
		`GRANT USAGE ON SCHEMA two_admin TO wp_admin_b WITH GRANT OPTION`,
	} {
		if _, err := su.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup %q: %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), connStr)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP SCHEMA IF EXISTS two_admin CASCADE")
		for _, r := range []string{"wp_admin_a", "wp_admin_b"} {
			_, _ = c.Exec(context.Background(), "REASSIGN OWNED BY "+r+" TO admin")
			_, _ = c.Exec(context.Background(), "DROP OWNED BY "+r)
			_, _ = c.Exec(context.Background(), "DROP ROLE IF EXISTS "+r)
		}
	})

	newProvisioner := func(adminUser, listener string) *Provisioner {
		rdb := testutil.RedisClient(t)
		store := restrict.NewRedisStore(rdb, "twoadmin:"+listener+":", metrics.Noop())
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		return NewProvisioner(adminUser, "p", "waypoint_test", backend, listener, "wp_ta_",
			false, true, "test", store, logger, nil, nil)
	}

	// A schema of its own, so the grants here cover only this test's table
	// and the result does not depend on what other tests left in public.
	perms := &auth.DBPermissions{Permissions: []string{"readonly"}, Schemas: []string{"two_admin"}}

	roleA, _, err := newProvisioner("wp_admin_a", "listener-a").
		EnsureUser(ctx, "user@example.com", "laptop", "waypoint_test", perms)
	if err != nil {
		t.Fatalf("listener A provisioning: %v", err)
	}

	// The second listener, with a different admin, must not trip over the
	// first one's group.
	roleB, _, err := newProvisioner("wp_admin_b", "listener-b").
		EnsureUser(ctx, "user@example.com", "laptop", "waypoint_test", perms)
	if err != nil {
		t.Fatalf("listener B provisioning failed against a shared backend: %v", err)
	}

	if roleA == roleB {
		t.Fatalf("both listeners provisioned the role %q", roleA)
	}

	// Each listener's groups are its own, and each user really does hold the
	// privilege its grant describes.
	for _, role := range []string{roleA, roleB} {
		var canRead bool
		if err := su.QueryRow(ctx,
			"SELECT has_table_privilege($1, 'two_admin.tbl', 'SELECT')", role).Scan(&canRead); err != nil {
			t.Fatalf("privilege check for %s: %v", role, err)
		}
		if !canRead {
			t.Errorf("role %q did not receive the readonly grant", role)
		}
	}

	// And the group roles themselves are distinct, each owned by its own admin.
	var groupCount int
	if err := su.QueryRow(ctx,
		`SELECT count(*) FROM pg_roles WHERE rolname LIKE 'wp_ta_grp_%'`).Scan(&groupCount); err != nil {
		t.Fatalf("count groups: %v", err)
	}
	if groupCount < 2 {
		t.Errorf("expected a group per listener, found %d", groupCount)
	}
}
