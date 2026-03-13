//go:build integration

package restrict_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

func TestIntegration_RedisStore_IncrDecrConns(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:")
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
	store := restrict.NewRedisStore(rdb, "inttest:")
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

func TestIntegration_RedisStore_BandwidthBytes(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:")
	ctx := context.Background()
	period := time.Hour

	total, err := store.AddBandwidthBytes(ctx, "alice", 500, period)
	if err != nil {
		t.Fatal(err)
	}
	if total != 500 {
		t.Fatalf("expected 500, got %d", total)
	}

	total, err = store.AddBandwidthBytes(ctx, "alice", 300, period)
	if err != nil {
		t.Fatal(err)
	}
	if total != 800 {
		t.Fatalf("expected 800, got %d", total)
	}

	got, err := store.GetBandwidthBytes(ctx, "alice", period)
	if err != nil {
		t.Fatal(err)
	}
	if got != 800 {
		t.Fatalf("expected 800 from get, got %d", got)
	}

	// Verify the key has a TTL set by checking via raw Redis client.
	bucket := time.Now().Unix() / int64(period.Seconds())
	key := fmt.Sprintf("inttest:bw:alice:%d_%d", int64(period.Seconds()), bucket)
	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil {
		t.Fatalf("TTL check: %v", err)
	}
	if ttl <= 0 {
		t.Fatalf("expected positive TTL, got %v", ttl)
	}
}

func TestIntegration_RedisStore_TouchAndGetLastUsed(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:")
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
