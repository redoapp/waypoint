//go:build integration

package provision

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

func setupCleaner(t *testing.T, ttl time.Duration) (*Cleaner, *Provisioner, *restrict.RedisStore) {
	t.Helper()
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	_, backend := testutil.PostgresBackend(t)

	provisioner := NewProvisioner("admin", "adminpass", "waypoint_test", backend, "wp_", store, logger)
	cleaner := NewCleaner("admin", "adminpass", "waypoint_test", backend, "wp_", ttl, store, logger)

	return cleaner, provisioner, store
}

func roleExists(t *testing.T, rolname string) bool {
	t.Helper()
	conn := adminConn(t)
	var exists bool
	err := conn.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", rolname).Scan(&exists)
	if err != nil {
		t.Fatalf("check role exists: %v", err)
	}
	return exists
}

func TestIntegration_Cleanup_DropsIdleUser(t *testing.T) {
	ttl := 2 * time.Second
	_, provisioner, store := setupCleaner(t, ttl)
	ctx := context.Background()

	pgUser, _, err := provisioner.EnsureUser(ctx, "idle@example.com", "idle-node", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupRole(t, pgUser) })

	if !roleExists(t, pgUser) {
		t.Fatalf("role %q should exist after provisioning", pgUser)
	}

	// Set lastused to the past (beyond TTL).
	rdb := testutil.RedisClientRaw(t)
	oldTime := time.Now().Add(-ttl - time.Minute)
	if err := rdb.Set(ctx, "inttest:lastused:"+pgUser, oldTime.Unix(), 0).Err(); err != nil {
		t.Fatal(err)
	}

	// Verify lastused is old.
	ts, err := store.GetLastUsed(ctx, pgUser)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(ts) < ttl {
		t.Fatalf("expected lastused to be old, got %v", ts)
	}

	// Verify no active connections.
	conn := adminConn(t)
	var activeConns int
	err = conn.QueryRow(ctx,
		"SELECT count(*) FROM pg_stat_activity WHERE usename = $1", pgUser).Scan(&activeConns)
	if err != nil {
		t.Fatal(err)
	}
	if activeConns != 0 {
		t.Fatalf("expected 0 active connections, got %d", activeConns)
	}

	// Drop the role directly using dropRole (the internal function used by cleanup).
	conn2 := adminConn(t)
	if err := dropRole(ctx, conn2, pgUser); err != nil {
		t.Fatalf("dropRole failed: %v", err)
	}

	if roleExists(t, pgUser) {
		t.Fatalf("role %q should have been dropped", pgUser)
	}
}

func TestIntegration_Cleanup_DropsIdleUser_ViaCleanupMethod(t *testing.T) {
	ttl := 2 * time.Second
	cleaner, provisioner, store := setupCleaner(t, ttl)
	ctx := context.Background()

	pgUser, _, err := provisioner.EnsureUser(ctx, "idle2@example.com", "idle2-node", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupRole(t, pgUser) })

	if !roleExists(t, pgUser) {
		t.Fatalf("role %q should exist after provisioning", pgUser)
	}

	// Set lastused to the past (beyond TTL).
	rdb := testutil.RedisClientRaw(t)
	oldTime := time.Now().Add(-ttl - time.Minute)
	if err := rdb.Set(ctx, "inttest:lastused:"+pgUser, oldTime.Unix(), 0).Err(); err != nil {
		t.Fatal(err)
	}

	ts, err := store.GetLastUsed(ctx, pgUser)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(ts) < ttl {
		t.Fatalf("expected lastused to be old, got %v", ts)
	}

	// Run the actual cleanup method — this should drop the idle role.
	cleaner.cleanup(ctx)

	if roleExists(t, pgUser) {
		t.Fatalf("role %q should have been dropped by cleanup()", pgUser)
	}
}

func TestIntegration_Cleanup_MultipleRoles_MixedState(t *testing.T) {
	ttl := 2 * time.Second
	cleaner, provisioner, _ := setupCleaner(t, ttl)
	ctx := context.Background()
	_, backend := testutil.PostgresBackend(t)
	rdb := testutil.RedisClientRaw(t)
	oldTime := time.Now().Add(-ttl - time.Minute)

	// Create 3 idle roles (should be dropped).
	var idleUsers []string
	for i := 0; i < 3; i++ {
		login := fmt.Sprintf("idle%d@example.com", i)
		node := fmt.Sprintf("idle%d-node", i)
		pgUser, _, err := provisioner.EnsureUser(ctx, login, node, "waypoint_test", nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cleanupRole(t, pgUser) })
		rdb.Set(ctx, "inttest:lastused:"+pgUser, oldTime.Unix(), 0)
		idleUsers = append(idleUsers, pgUser)
	}

	// Create 2 recent roles (should survive).
	var recentUsers []string
	for i := 0; i < 2; i++ {
		login := fmt.Sprintf("recent%d@example.com", i)
		node := fmt.Sprintf("recent%d-node", i)
		pgUser, _, err := provisioner.EnsureUser(ctx, login, node, "waypoint_test", nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cleanupRole(t, pgUser) })
		recentUsers = append(recentUsers, pgUser)
	}

	// Create 1 connected role (should survive).
	pgUser, password, err := provisioner.EnsureUser(ctx, "connected_multi@example.com", "conn-multi-node", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupRole(t, pgUser) })
	rdb.Set(ctx, "inttest:lastused:"+pgUser, oldTime.Unix(), 0)
	connStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, backend)
	userConn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		t.Fatal(err)
	}
	defer userConn.Close(ctx)

	// Run cleanup.
	cleaner.cleanup(ctx)

	// Idle roles should be gone.
	for _, u := range idleUsers {
		if roleExists(t, u) {
			t.Errorf("idle role %q should have been dropped", u)
		}
	}

	// Recent roles should survive.
	for _, u := range recentUsers {
		if !roleExists(t, u) {
			t.Errorf("recent role %q should have survived", u)
		}
	}

	// Connected role should survive.
	if !roleExists(t, pgUser) {
		t.Errorf("connected role %q should have survived", pgUser)
	}
}

func TestIntegration_Cleanup_SkipsRecentUser(t *testing.T) {
	ttl := 1 * time.Hour
	cleaner, provisioner, _ := setupCleaner(t, ttl)
	ctx := context.Background()

	pgUser, _, err := provisioner.EnsureUser(ctx, "recent@example.com", "recent-node", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupRole(t, pgUser) })

	// Last used is set by EnsureUser (just now), so it's within TTL.
	cleaner.cleanup(ctx)

	// Role should still exist.
	if !roleExists(t, pgUser) {
		t.Fatalf("role %q should survive cleanup (recently used)", pgUser)
	}
}

func TestIntegration_Cleanup_Run_StopsOnCancel(t *testing.T) {
	ttl := 2 * time.Second
	cleaner, provisioner, _ := setupCleaner(t, ttl)
	ctx := context.Background()

	pgUser, _, err := provisioner.EnsureUser(ctx, "run_cancel@example.com", "run-cancel-node", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupRole(t, pgUser) })

	// Set lastused to the past so cleanup will drop it.
	rdb := testutil.RedisClientRaw(t)
	oldTime := time.Now().Add(-ttl - time.Minute)
	if err := rdb.Set(ctx, "inttest:lastused:"+pgUser, oldTime.Unix(), 0).Err(); err != nil {
		t.Fatal(err)
	}

	// Run with a cancellable context — should run cleanup at least once then stop.
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		cleaner.Run(runCtx)
		close(done)
	}()

	// Give Run time to execute cleanup once.
	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Run returned after cancel — good.
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}

	// Verify the idle role was dropped during Run.
	if roleExists(t, pgUser) {
		t.Fatalf("role %q should have been dropped by Run()", pgUser)
	}
}

func TestIntegration_Cleanup_DropRole_PartialFailure(t *testing.T) {
	ctx := context.Background()

	// Create a role that owns nothing — all REVOKE/DROP OWNED statements
	// will succeed trivially. This tests the happy path through dropRole.
	conn := adminConn(t)

	rolname := "wp_partialfail_test"
	_, err := conn.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", pgx.Identifier{rolname}.Sanitize()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(ctx, fmt.Sprintf("CREATE ROLE %s", pgx.Identifier{rolname}.Sanitize()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := adminConn(t)
		c.Exec(context.Background(), fmt.Sprintf("DROP ROLE IF EXISTS %s", pgx.Identifier{rolname}.Sanitize()))
	})

	// dropRole should handle this cleanly.
	conn2 := adminConn(t)
	if err := dropRole(ctx, conn2, rolname); err != nil {
		t.Fatalf("dropRole failed: %v", err)
	}

	if roleExists(t, rolname) {
		t.Fatalf("role %q should have been dropped", rolname)
	}
}

func TestIntegration_Cleanup_SkipsConnectedUser(t *testing.T) {
	ttl := 2 * time.Second
	cleaner, provisioner, _ := setupCleaner(t, ttl)
	ctx := context.Background()
	_, backend := testutil.PostgresBackend(t)

	pgUser, password, err := provisioner.EnsureUser(ctx, "connected@example.com", "conn-node", "waypoint_test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupRole(t, pgUser) })

	// Set last used to the past so cleanup would normally drop it.
	rdb := testutil.RedisClientRaw(t)
	oldTime := time.Now().Add(-ttl - time.Minute)
	if err := rdb.Set(ctx, "inttest:lastused:"+pgUser, oldTime.Unix(), 0).Err(); err != nil {
		t.Fatal(err)
	}

	// Hold an open connection as the provisioned user.
	userConnStr := fmt.Sprintf("postgres://%s:%s@%s/waypoint_test?sslmode=disable", pgUser, password, backend)
	userConn, err := pgx.Connect(ctx, userConnStr)
	if err != nil {
		t.Fatalf("login as provisioned user: %v", err)
	}
	defer userConn.Close(ctx)

	// Run cleanup — should skip because user has active connections.
	cleaner.cleanup(ctx)

	// Role should still exist.
	if !roleExists(t, pgUser) {
		t.Fatalf("role %q should survive cleanup (has active connection)", pgUser)
	}
}
