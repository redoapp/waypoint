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
	return NewProvisioner(db.adminUser, db.adminPass, "waypoint_test", db.backend, "wp_", false, true, "test", store, logger, nil, nil)
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

// memberOfPresetGroups returns the wp_grp_ memberships of pgUser, used by
// integration tests that assert on group-membership reconciliation.
func memberOfPresetGroups(t *testing.T, db dbBackend, pgUser string) []string {
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
		if strings.HasPrefix(name, "wp_grp_") {
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

			got := memberOfPresetGroups(t, db, pgUser)
			if len(got) != 1 || got[0] != "wp_grp_readonly_public_waypoint_test" {
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

			before := memberOfPresetGroups(t, db, pgUser)

			// Second EnsureUser with identical perms should be a no-op for
			// membership state — the steady-state path that needs to be cheap.
			if _, _, err := p.EnsureUser(ctx, "stable@example.com", "stable-node", "waypoint_test", perms); err != nil {
				t.Fatalf("second EnsureUser: %v", err)
			}

			after := memberOfPresetGroups(t, db, pgUser)
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

			before := memberOfPresetGroups(t, db, pgUser)
			if len(before) != 1 || before[0] != "wp_grp_readwrite_public_waypoint_test" {
				t.Fatalf("expected wp_grp_readwrite_public_waypoint_test, got %v", before)
			}

			if _, _, err := p.EnsureUser(ctx, "diff@example.com", "diff-node", "waypoint_test",
				&auth.DBPermissions{Permissions: []string{"readonly"}}); err != nil {
				t.Fatal(err)
			}

			after := memberOfPresetGroups(t, db, pgUser)
			if len(after) != 1 || after[0] != "wp_grp_readonly_public_waypoint_test" {
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

			groups := memberOfPresetGroups(t, db, pgUser)
			if len(groups) != 1 {
				t.Fatalf("expected exactly 1 group membership, got %v", groups)
			}
			if !strings.HasPrefix(groups[0], "wp_grp_perms_") {
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

			before := memberOfPresetGroups(t, db, pgUser)
			if len(before) != 1 || !strings.HasPrefix(before[0], "wp_grp_readonly_") {
				t.Fatalf("expected initial readonly group, got %v", before)
			}

			if _, _, err := p.EnsureUser(ctx, "switch@example.com", "switch-node", "waypoint_test",
				&auth.DBPermissions{
					Permissions: []string{"readonly"},
					SQL:         []string{"GRANT SELECT ON public.switch_target TO {{.Role}}"},
				}); err != nil {
				t.Fatal(err)
			}

			after := memberOfPresetGroups(t, db, pgUser)
			if len(after) != 1 || !strings.HasPrefix(after[0], "wp_grp_perms_") {
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

			groups := memberOfPresetGroups(t, db, pgUser)
			want := map[string]bool{
				"wp_grp_readonly_public_waypoint_test":      true,
				"wp_grp_readonly_multi_audit_waypoint_test": true,
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
