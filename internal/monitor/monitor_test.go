package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTest(t *testing.T) (*miniredis.Miniredis, *Store) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return mr, NewStore(rdb, "wp:")
}

func TestDiscoverInstances(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	// Set up an instance heartbeat.
	mr.HSet("wp:instance:abc-123", "hostname", "host1")
	mr.HSet("wp:instance:abc-123", "started_at", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	mr.HSet("wp:instance:abc-123", "heartbeat_at", time.Now().UTC().Format(time.RFC3339))
	mr.HSet("wp:instance:abc-123", "listeners", "[]")
	mr.HSet("wp:instance:abc-123", "active_conns", "3")
	mr.HSet("wp:instance:abc-123", "total_conns", "50")
	mr.HSet("wp:instance:abc-123", "bytes_read", "1024")
	mr.HSet("wp:instance:abc-123", "bytes_written", "2048")

	instances, err := store.DiscoverInstances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 1 {
		t.Fatalf("got %d instances, want 1", len(instances))
	}

	inst := instances[0]
	if inst.ID != "abc-123" {
		t.Errorf("ID = %q, want %q", inst.ID, "abc-123")
	}
	if inst.Hostname != "host1" {
		t.Errorf("Hostname = %q, want %q", inst.Hostname, "host1")
	}
	if inst.ActiveConns != 3 {
		t.Errorf("ActiveConns = %d, want 3", inst.ActiveConns)
	}
	if inst.TotalConns != 50 {
		t.Errorf("TotalConns = %d, want 50", inst.TotalConns)
	}
	if inst.BytesRead != 1024 {
		t.Errorf("BytesRead = %d, want 1024", inst.BytesRead)
	}

	status := inst.HealthStatus()
	if status != "healthy" {
		t.Errorf("HealthStatus = %q, want %q", status, "healthy")
	}
}

func TestListUsers(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.Set("wp:conns:alice@example.com", "2")
	mr.Set("wp:bytes:alice@example.com", "500000")
	mr.Set("wp:conns:bob@example.com", "1")

	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}

	// Users should be sorted by name.
	if users[0].LoginName != "alice@example.com" {
		t.Errorf("first user = %q, want alice@example.com", users[0].LoginName)
	}
	if users[0].ActiveConns != 2 {
		t.Errorf("alice conns = %d, want 2", users[0].ActiveConns)
	}
	if users[0].TotalBytes != 500000 {
		t.Errorf("alice bytes = %d, want 500000", users[0].TotalBytes)
	}
	if users[1].LoginName != "bob@example.com" {
		t.Errorf("second user = %q, want bob@example.com", users[1].LoginName)
	}
}

func TestResetConns(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.Set("wp:conns:alice@example.com", "5")

	if err := store.ResetConns(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	if mr.Exists("wp:conns:alice@example.com") {
		t.Error("conns key should be deleted")
	}
}

func TestResetBytes(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.Set("wp:bytes:alice@example.com", "999999")

	if err := store.ResetBytes(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	if mr.Exists("wp:bytes:alice@example.com") {
		t.Error("bytes key should be deleted")
	}
}

func TestResetAll(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.Set("wp:conns:alice@example.com", "5")
	mr.Set("wp:bytes:alice@example.com", "999999")

	if err := store.ResetAll(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	if mr.Exists("wp:conns:alice@example.com") {
		t.Error("conns key should be deleted")
	}
	if mr.Exists("wp:bytes:alice@example.com") {
		t.Error("bytes key should be deleted")
	}
}

func TestGetUserStats(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.Set("wp:conns:alice@example.com", "3")
	mr.Set("wp:bytes:alice@example.com", "12345")

	stats, err := store.GetUserStats(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if stats.LoginName != "alice@example.com" {
		t.Errorf("LoginName = %q, want alice@example.com", stats.LoginName)
	}
	if stats.ActiveConns != 3 {
		t.Errorf("ActiveConns = %d, want 3", stats.ActiveConns)
	}
	if stats.TotalBytes != 12345 {
		t.Errorf("TotalBytes = %d, want 12345", stats.TotalBytes)
	}
}

func TestHealthStatus(t *testing.T) {
	tests := []struct {
		age    time.Duration
		status string
	}{
		{5 * time.Second, "healthy"},
		{20 * time.Second, "warning"},
		{30 * time.Second, "critical"},
	}

	for _, tt := range tests {
		info := InstanceInfo{HeartbeatAt: time.Now().Add(-tt.age)}
		if got := info.HealthStatus(); got != tt.status {
			t.Errorf("age=%v: HealthStatus = %q, want %q", tt.age, got, tt.status)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30 seconds"},
		{1 * time.Minute, "1 minute"},
		{5 * time.Minute, "5 minutes"},
		{1 * time.Hour, "1 hour"},
		{24 * time.Hour, "1 day"},
		{72 * time.Hour, "3 days"},
	}
	for _, tt := range tests {
		if got := formatDuration(tt.d); got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
