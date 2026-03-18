package monitor

import (
	"context"
	"strconv"
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

func TestUptime(t *testing.T) {
	info := InstanceInfo{StartedAt: time.Now().Add(-5 * time.Minute)}
	uptime := info.Uptime()
	if uptime < 4*time.Minute || uptime > 6*time.Minute {
		t.Errorf("Uptime = %v, want ~5m", uptime)
	}
}

func TestNewStore_DefaultPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	store := NewStore(rdb, "") // empty prefix should default to "waypoint:"
	ctx := context.Background()

	mr.HSet("waypoint:instance:def-456", "hostname", "default-host")
	mr.HSet("waypoint:instance:def-456", "started_at", time.Now().UTC().Format(time.RFC3339))
	mr.HSet("waypoint:instance:def-456", "heartbeat_at", time.Now().UTC().Format(time.RFC3339))
	mr.HSet("waypoint:instance:def-456", "listeners", "[]")
	mr.HSet("waypoint:instance:def-456", "active_conns", "0")
	mr.HSet("waypoint:instance:def-456", "total_conns", "0")
	mr.HSet("waypoint:instance:def-456", "bytes_read", "0")
	mr.HSet("waypoint:instance:def-456", "bytes_written", "0")

	instances, err := store.DiscoverInstances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 1 {
		t.Fatalf("got %d instances, want 1", len(instances))
	}
	if instances[0].Hostname != "default-host" {
		t.Errorf("Hostname = %q, want %q", instances[0].Hostname, "default-host")
	}
}

func TestResetBandwidth(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.HSet("wp:bw:alice@example.com:3600", "100", "5000")

	if err := store.ResetBandwidth(ctx, "alice@example.com", 3600); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("wp:bw:alice@example.com:3600") {
		t.Error("bandwidth key should be deleted")
	}
}

func TestResetAll_WithBandwidth(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.Set("wp:conns:alice@example.com", "5")
	mr.Set("wp:bytes:alice@example.com", "999999")
	mr.HSet("wp:bw:alice@example.com:3600", "100", "5000")

	if err := store.ResetAll(ctx, "alice@example.com"); err != nil {
		t.Fatal(err)
	}

	if mr.Exists("wp:conns:alice@example.com") {
		t.Error("conns key should be deleted")
	}
	if mr.Exists("wp:bytes:alice@example.com") {
		t.Error("bytes key should be deleted")
	}
	if mr.Exists("wp:bw:alice@example.com:3600") {
		t.Error("bandwidth key should be deleted")
	}
}

func TestGetUserStats_WithBandwidth(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.Set("wp:conns:alice@example.com", "2")
	mr.Set("wp:bytes:alice@example.com", "10000")

	// Set up bandwidth hash with a bucket that falls within the sliding window.
	now := time.Now().Unix()
	bSize := int64(10) // for 3600s period: 3600/360 = 10
	currentBucket := now / bSize
	mr.HSet("wp:bw:alice@example.com:3600",
		strconv.FormatInt(currentBucket, 10), "5000",
		strconv.FormatInt(currentBucket-1, 10), "3000",
	)

	stats, err := store.GetUserStats(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if stats.ActiveConns != 2 {
		t.Errorf("ActiveConns = %d, want 2", stats.ActiveConns)
	}
	if stats.TotalBytes != 10000 {
		t.Errorf("TotalBytes = %d, want 10000", stats.TotalBytes)
	}
	if len(stats.Bandwidth) != 1 {
		t.Fatalf("got %d bandwidth entries, want 1", len(stats.Bandwidth))
	}
	bw := stats.Bandwidth[0]
	if bw.Bytes != 8000 {
		t.Errorf("Bandwidth.Bytes = %d, want 8000", bw.Bytes)
	}
	if bw.PeriodStr != "1 hour" {
		t.Errorf("PeriodStr = %q, want %q", bw.PeriodStr, "1 hour")
	}
}

func TestGetUserStats_MultiplePeriods(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	now := time.Now().Unix()

	// 1h period: bSize = 3600/360 = 10
	bSize1h := int64(10)
	bucket1h := now / bSize1h
	mr.HSet("wp:bw:alice@example.com:3600",
		strconv.FormatInt(bucket1h, 10), "1000",
	)

	// 1d period: bSize = 86400/360 = 240
	bSize1d := int64(240)
	bucket1d := now / bSize1d
	mr.HSet("wp:bw:alice@example.com:86400",
		strconv.FormatInt(bucket1d, 10), "9000",
	)

	stats, err := store.GetUserStats(ctx, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Bandwidth) != 2 {
		t.Fatalf("got %d bandwidth entries, want 2", len(stats.Bandwidth))
	}
	// Should be sorted by period: 1h first, then 1d.
	if stats.Bandwidth[0].PeriodStr != "1 hour" {
		t.Errorf("first period = %q, want %q", stats.Bandwidth[0].PeriodStr, "1 hour")
	}
	if stats.Bandwidth[1].PeriodStr != "1 day" {
		t.Errorf("second period = %q, want %q", stats.Bandwidth[1].PeriodStr, "1 day")
	}
	if stats.Bandwidth[0].Bytes != 1000 {
		t.Errorf("1h bytes = %d, want 1000", stats.Bandwidth[0].Bytes)
	}
	if stats.Bandwidth[1].Bytes != 9000 {
		t.Errorf("1d bytes = %d, want 9000", stats.Bandwidth[1].Bytes)
	}
}

func TestListUsers_WithBandwidth(t *testing.T) {
	mr, store := setupTest(t)
	ctx := context.Background()

	mr.Set("wp:conns:alice@example.com", "1")
	mr.Set("wp:conns:bob@example.com", "2")

	now := time.Now().Unix()
	bSize := int64(10)
	bucket := now / bSize

	mr.HSet("wp:bw:alice@example.com:3600",
		strconv.FormatInt(bucket, 10), "4000",
	)
	mr.HSet("wp:bw:bob@example.com:3600",
		strconv.FormatInt(bucket, 10), "6000",
	)

	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}

	// Sorted by name: alice first.
	if users[0].LoginName != "alice@example.com" {
		t.Errorf("first user = %q, want alice@example.com", users[0].LoginName)
	}
	if len(users[0].Bandwidth) != 1 {
		t.Fatalf("alice bandwidth entries = %d, want 1", len(users[0].Bandwidth))
	}
	if users[0].Bandwidth[0].Bytes != 4000 {
		t.Errorf("alice bandwidth bytes = %d, want 4000", users[0].Bandwidth[0].Bytes)
	}

	if users[1].LoginName != "bob@example.com" {
		t.Errorf("second user = %q, want bob@example.com", users[1].LoginName)
	}
	if len(users[1].Bandwidth) != 1 {
		t.Fatalf("bob bandwidth entries = %d, want 1", len(users[1].Bandwidth))
	}
	if users[1].Bandwidth[0].Bytes != 6000 {
		t.Errorf("bob bandwidth bytes = %d, want 6000", users[1].Bandwidth[0].Bytes)
	}
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
