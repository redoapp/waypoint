//go:build integration

package restrict_test

import (
	"context"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

func TestIntegration_RedisStore_IncrDecrConns(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	ctx := context.Background()

	// Increment twice.
	count, err := store.IncrConns(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}

	count, err = store.IncrConns(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}

	// Decrement once, verify count.
	if err := store.DecrConns(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetConns(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("expected 1 after decr, got %d", got)
	}

	// Decrement to zero, key should be deleted.
	if err := store.DecrConns(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetConns(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("expected 0 after decr to zero, got %d", got)
	}
}

func TestIntegration_RedisStore_AddBytes(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	ctx := context.Background()

	total, err := store.AddBytes(ctx, "alice", 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 100 {
		t.Fatalf("expected 100, got %d", total)
	}

	total, err = store.AddBytes(ctx, "alice", 250)
	if err != nil {
		t.Fatal(err)
	}
	if total != 350 {
		t.Fatalf("expected 350, got %d", total)
	}
}

func TestIntegration_RedisStore_BandwidthSlidingWindow(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	ctx := context.Background()
	tiers := []auth.BandwidthTier{{Bytes: 100000, Period: time.Hour}}

	result, err := store.AddBandwidthBytesMulti(ctx, "alice", 500, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if result.Exceeded {
		t.Fatal("did not expect limit exceeded")
	}

	result, err = store.AddBandwidthBytesMulti(ctx, "alice", 300, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if result.Exceeded {
		t.Fatal("did not expect limit exceeded")
	}

	got, err := store.GetBandwidthBytes(ctx, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got != 800 {
		t.Fatalf("expected 800 from get, got %d", got)
	}
}

func TestIntegration_RedisStore_BandwidthMultiTier(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	ctx := context.Background()
	tiers := []auth.BandwidthTier{
		{Bytes: 1000, Period: time.Hour},
		{Bytes: 5000, Period: 24 * time.Hour},
	}

	// Under both limits.
	result, err := store.AddBandwidthBytesMulti(ctx, "multitier_user", 500, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if result.Exceeded {
		t.Fatal("did not expect limit exceeded")
	}

	// Exceed hourly.
	result, err = store.AddBandwidthBytesMulti(ctx, "multitier_user", 600, tiers)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Exceeded {
		t.Fatal("expected hourly limit exceeded")
	}
	if result.ExceededTier != 0 {
		t.Fatalf("expected tier 0 exceeded, got %d", result.ExceededTier)
	}
}

func TestIntegration_RedisStore_TouchAndGetLastUsed(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
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
		t.Fatalf("timestamp %v not in expected range [%v, %v]", ts, before, after)
	}

	// Non-existent user returns zero time.
	ts, err = store.GetLastUsed(ctx, "nobody")
	if err != nil {
		t.Fatal(err)
	}
	if !ts.IsZero() {
		t.Fatalf("expected zero time for nonexistent, got %v", ts)
	}
}
