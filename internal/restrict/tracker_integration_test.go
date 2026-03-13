//go:build integration

package restrict_test

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

func TestIntegration_Tracker_AcquireRelease(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := restrict.NewTracker(store, metrics.Noop(), logger)
	ctx := context.Background()
	limits := auth.MergedLimits{MaxConns: 2}

	release1, err := tracker.Acquire(ctx, "alice", limits)
	if err != nil {
		t.Fatal(err)
	}

	release2, err := tracker.Acquire(ctx, "alice", limits)
	if err != nil {
		t.Fatal(err)
	}

	// Third should fail.
	_, err = tracker.Acquire(ctx, "alice", limits)
	if err == nil {
		t.Fatal("expected error on third acquire")
	}

	// Release one, then acquire should work.
	release1()

	release3, err := tracker.Acquire(ctx, "alice", limits)
	if err != nil {
		t.Fatalf("expected success after release: %v", err)
	}

	release2()
	release3()
}

func TestIntegration_Tracker_ConcurrentAcquire(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := restrict.NewTracker(store, metrics.Noop(), logger)
	ctx := context.Background()

	const maxConns = 5
	const goroutines = 20
	limits := auth.MergedLimits{MaxConns: maxConns}

	var successes atomic.Int64
	var failures atomic.Int64
	var releaseFns []func()
	var mu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			release, err := tracker.Acquire(ctx, "concurrent_user", limits)
			if err != nil {
				failures.Add(1)
				return
			}
			successes.Add(1)
			mu.Lock()
			releaseFns = append(releaseFns, release)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// At most maxConns should succeed (could be fewer due to race check-then-act).
	if successes.Load() > maxConns {
		t.Fatalf("expected at most %d successes, got %d", maxConns, successes.Load())
	}
	if successes.Load() == 0 {
		t.Fatal("expected at least one success")
	}

	t.Logf("concurrent acquire: %d successes, %d failures", successes.Load(), failures.Load())

	// Clean up.
	for _, fn := range releaseFns {
		fn()
	}
}

func TestIntegration_Tracker_HighConcurrencyStress(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := restrict.NewTracker(store, metrics.Noop(), logger)
	ctx := context.Background()

	const maxConns = 10
	const goroutines = 200
	limits := auth.MergedLimits{MaxConns: maxConns}

	var successes atomic.Int64
	var releaseFns []func()
	var mu sync.Mutex

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			release, err := tracker.Acquire(ctx, "stress_user", limits)
			if err != nil {
				return
			}
			successes.Add(1)
			mu.Lock()
			releaseFns = append(releaseFns, release)
			mu.Unlock()
		}()
	}

	wg.Wait()

	if successes.Load() > int64(maxConns) {
		t.Fatalf("limit violated: %d acquired, max is %d", successes.Load(), maxConns)
	}
	if successes.Load() == 0 {
		t.Fatal("expected at least one success")
	}

	t.Logf("stress test: %d/%d acquired (limit %d)", successes.Load(), goroutines, maxConns)

	// Release all, then verify Redis counter returns to zero.
	for _, fn := range releaseFns {
		fn()
	}

	conns, err := store.GetConns(ctx, "stress_user")
	if err != nil {
		t.Fatal(err)
	}
	if conns != 0 {
		t.Fatalf("expected 0 conns after full release, got %d", conns)
	}
}

func TestIntegration_Tracker_AcquireReleaseCycle_CountConsistency(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := restrict.NewTracker(store, metrics.Noop(), logger)
	ctx := context.Background()

	const maxConns = 5
	const cycles = 50
	limits := auth.MergedLimits{MaxConns: maxConns}

	// Repeatedly acquire and release, checking count stays consistent.
	for i := 0; i < cycles; i++ {
		var releases []func()
		for j := 0; j < maxConns; j++ {
			release, err := tracker.Acquire(ctx, "cycle_user", limits)
			if err != nil {
				t.Fatalf("cycle %d, acquire %d: %v", i, j, err)
			}
			releases = append(releases, release)
		}

		// Should be at limit.
		_, err := tracker.Acquire(ctx, "cycle_user", limits)
		if err == nil {
			t.Fatalf("cycle %d: should be at limit", i)
		}

		for _, fn := range releases {
			fn()
		}
	}

	// After all cycles, count should be zero.
	conns, err := store.GetConns(ctx, "cycle_user")
	if err != nil {
		t.Fatal(err)
	}
	if conns != 0 {
		t.Fatalf("expected 0 conns after %d cycles, got %d", cycles, conns)
	}
}
