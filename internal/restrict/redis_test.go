package restrict

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupRedis(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return NewRedisStore(rdb, "test:"), mr
}

func TestNewRedisStore_DefaultPrefix(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	store := NewRedisStore(rdb, "")
	if store.keyPrefix != "waypoint:" {
		t.Errorf("expected default prefix, got %q", store.keyPrefix)
	}
}

func TestRedisStore_Key(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	store := NewRedisStore(rdb, "wp:")
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

func TestRedisStore_BandwidthBytes(t *testing.T) {
	store, _ := setupRedis(t)
	ctx := context.Background()
	period := time.Hour

	total, err := store.AddBandwidthBytes(ctx, "alice", 500, period)
	if err != nil {
		t.Fatal(err)
	}
	if total != 500 {
		t.Errorf("expected 500, got %d", total)
	}

	total, err = store.AddBandwidthBytes(ctx, "alice", 300, period)
	if err != nil {
		t.Fatal(err)
	}
	if total != 800 {
		t.Errorf("expected 800, got %d", total)
	}

	got, err := store.GetBandwidthBytes(ctx, "alice", period)
	if err != nil {
		t.Fatal(err)
	}
	if got != 800 {
		t.Errorf("expected 800, got %d", got)
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
