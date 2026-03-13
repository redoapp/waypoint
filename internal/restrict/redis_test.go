package restrict

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
)

func setupRedis(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return NewRedisStore(rdb, "test:", metrics.Noop()), mr
}

func TestNewRedisStore_DefaultPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	store := NewRedisStore(rdb, "", metrics.Noop())
	if store.keyPrefix != "waypoint:" {
		t.Errorf("expected default prefix, got %q", store.keyPrefix)
	}
}

func TestRedisStore_Key(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	store := NewRedisStore(rdb, "wp:", metrics.Noop())
	got := store.key("conns", "alice")
	if got != "wp:conns:alice" {
		t.Errorf("expected wp:conns:alice, got %q", got)
	}
}

func TestRedisStore_IncrDecrConns(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()

	count, err := store.IncrConns(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}

	count, err = store.IncrConns(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}

	if err := store.DecrConns(ctx, "alice"); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetConns(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("expected 1 after decr, got %d", got)
	}
}

func TestRedisStore_DecrConnsToZero_Cleanup(t *testing.T) {
	store, mr := setupRedis(t)
	ctx := context.Background()

	store.IncrConns(ctx, "bob")
	store.DecrConns(ctx, "bob")

	// Key should be deleted.
	if mr.Exists(store.key("conns", "bob")) {
		t.Error("expected key to be deleted at zero")
	}
}

func TestRedisStore_GetConns_NonExistent(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()

	count, err := store.GetConns(ctx, "nobody")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 for nonexistent user, got %d", count)
	}
}

func TestRedisStore_AddBytes(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()

	total, err := store.AddBytes(ctx, "alice", 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 100 {
		t.Errorf("expected 100, got %d", total)
	}

	total, err = store.AddBytes(ctx, "alice", 200)
	if err != nil {
		t.Fatal(err)
	}
	if total != 300 {
		t.Errorf("expected 300, got %d", total)
	}
}

func TestRedisStore_BandwidthSlidingWindow(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()
	tiers := []auth.BandwidthTier{{Bytes: 10000, Period: time.Hour}}

	result, err := store.AddBandwidthBytesMulti(ctx, "alice", 500, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if result.Exceeded {
		t.Error("did not expect limit exceeded")
	}

	result, err = store.AddBandwidthBytesMulti(ctx, "alice", 300, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if result.Exceeded {
		t.Error("did not expect limit exceeded")
	}

	got, err := store.GetBandwidthBytes(ctx, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got != 800 {
		t.Errorf("expected 800, got %d", got)
	}
}

func TestRedisStore_BandwidthSlidingWindow_LimitExceeded(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()
	tiers := []auth.BandwidthTier{{Bytes: 100, Period: time.Hour}}

	result, err := store.AddBandwidthBytesMulti(ctx, "alice", 150, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Exceeded {
		t.Error("expected limit exceeded")
	}
	if result.ExceededTier != 0 {
		t.Errorf("expected exceeded tier 0, got %d", result.ExceededTier)
	}
}

func TestRedisStore_BandwidthSlidingWindow_MultiTier(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()
	tiers := []auth.BandwidthTier{
		{Bytes: 1000, Period: time.Hour},        // hourly limit
		{Bytes: 10000, Period: 168 * time.Hour}, // weekly limit
	}

	// Add bytes under both limits.
	result, err := store.AddBandwidthBytesMulti(ctx, "alice", 500, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if result.Exceeded {
		t.Error("should not exceed either tier")
	}

	// Add more to exceed hourly but not weekly.
	result, err = store.AddBandwidthBytesMulti(ctx, "alice", 600, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Exceeded {
		t.Error("expected hourly limit exceeded")
	}
	if result.ExceededTier != 0 {
		t.Errorf("expected exceeded tier 0 (hourly), got %d", result.ExceededTier)
	}
}

func TestRedisStore_BandwidthSlidingWindow_WeeklyExceeded(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()
	tiers := []auth.BandwidthTier{
		{Bytes: 10000, Period: time.Hour},     // generous hourly
		{Bytes: 500, Period: 168 * time.Hour}, // tight weekly
	}

	result, err := store.AddBandwidthBytesMulti(ctx, "alice", 600, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Exceeded {
		t.Error("expected weekly limit exceeded")
	}
	if result.ExceededTier != 1 {
		t.Errorf("expected exceeded tier 1 (weekly), got %d", result.ExceededTier)
	}
}

func TestRedisStore_BandwidthSlidingWindow_OldBucketsExpire(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()

	// Use a short period so bucket boundaries are easy to test.
	period := 100 * time.Second // bucketSize = max(10, 100/360) = 10s
	tiers := []auth.BandwidthTier{{Bytes: 10000, Period: period}}

	// Fix time at a known point.
	baseTime := time.Unix(1000, 0)
	store.nowFunc = func() time.Time { return baseTime }

	store.AddBandwidthBytesMulti(ctx, "alice", 500, tiers)

	// Read at the same time — should see 500.
	got, err := store.GetBandwidthBytes(ctx, "alice", period)
	if err != nil {
		t.Fatal(err)
	}
	if got != 500 {
		t.Errorf("expected 500, got %d", got)
	}

	// Advance time past the period — old buckets should fall out of the window.
	store.nowFunc = func() time.Time { return baseTime.Add(period + 10*time.Second) }

	got, err = store.GetBandwidthBytes(ctx, "alice", period)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("expected 0 after window expired, got %d", got)
	}
}

func TestRedisStore_BandwidthSlidingWindow_PartialExpiry(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()

	// 100s period → 10s buckets → 10 buckets per period
	period := 100 * time.Second
	tiers := []auth.BandwidthTier{{Bytes: 100000, Period: period}}

	baseTime := time.Unix(1000, 0)
	store.nowFunc = func() time.Time { return baseTime }

	// Write 500 bytes at t=1000 (bucket 100)
	store.AddBandwidthBytesMulti(ctx, "alice", 500, tiers)

	// Advance 50s, write 300 more (bucket 105)
	store.nowFunc = func() time.Time { return baseTime.Add(50 * time.Second) }
	store.AddBandwidthBytesMulti(ctx, "alice", 300, tiers)

	// At t+50s, both buckets are within the 100s window.
	got, err := store.GetBandwidthBytes(ctx, "alice", period)
	if err != nil {
		t.Fatal(err)
	}
	if got != 800 {
		t.Errorf("expected 800 at t+50s, got %d", got)
	}

	// Advance another 60s (total +110s from base). The first bucket (t=1000) is
	// now outside the 100s window, but the second (t=1050) is still valid.
	store.nowFunc = func() time.Time { return baseTime.Add(110 * time.Second) }
	got, err = store.GetBandwidthBytes(ctx, "alice", period)
	if err != nil {
		t.Fatal(err)
	}
	if got != 300 {
		t.Errorf("expected 300 after partial expiry, got %d", got)
	}
}

func TestRedisStore_BandwidthBytes_NonExistent(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()

	got, err := store.GetBandwidthBytes(ctx, "nobody", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("expected 0, got %d", got)
	}
}

func TestRedisStore_TouchAndGetLastUsed(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()

	before := time.Now().Add(-time.Second)
	if err := store.TouchLastUsed(ctx, "wp_alice_laptop_appdb"); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(time.Second)

	ts, err := store.GetLastUsed(ctx, "wp_alice_laptop_appdb")
	if err != nil {
		t.Fatal(err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Errorf("timestamp %v not in expected range [%v, %v]", ts, before, after)
	}
}

func TestRedisStore_GetLastUsed_NonExistent(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()

	ts, err := store.GetLastUsed(ctx, "nobody")
	if err != nil {
		t.Fatal(err)
	}
	if !ts.IsZero() {
		t.Errorf("expected zero time for nonexistent, got %v", ts)
	}
}

func TestBucketSize(t *testing.T) {
	tests := []struct {
		period   time.Duration
		expected int64
	}{
		{time.Hour, 10},         // 3600/360 = 10
		{24 * time.Hour, 240},   // 86400/360 = 240 (4 min)
		{168 * time.Hour, 1680}, // 604800/360 = 1680 (~28 min)
		{30 * time.Second, 10},  // 30/360 < 10, clamped to 10
	}

	for _, tt := range tests {
		got := bucketSize(tt.period)
		if got != tt.expected {
			t.Errorf("bucketSize(%v) = %d, want %d", tt.period, got, tt.expected)
		}
	}
}
