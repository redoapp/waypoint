package restrict

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/auth"
)

func setupTracker(t *testing.T) (*Tracker, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	store := NewRedisStore(rdb, "test:")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewTracker(store, logger), mr
}

func TestTracker_AcquireAndRelease(t *testing.T) {
	tracker, _ := setupTracker(t)
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

	// Release one, then acquire should work again.
	release1()
	release3, err := tracker.Acquire(ctx, "alice", limits)
	if err != nil {
		t.Fatalf("expected success after release, got: %v", err)
	}

	release2()
	release3()
}

func TestTracker_AcquireNoLimit(t *testing.T) {
	tracker, _ := setupTracker(t)
	ctx := context.Background()
	limits := auth.MergedLimits{} // no limit

	for i := 0; i < 100; i++ {
		release, err := tracker.Acquire(ctx, "bob", limits)
		if err != nil {
			t.Fatalf("acquire %d failed: %v", i, err)
		}
		defer release()
	}
}

func TestTracker_ReleaseIdempotent(t *testing.T) {
	tracker, _ := setupTracker(t)
	ctx := context.Background()
	limits := auth.MergedLimits{MaxConns: 1}

	release, err := tracker.Acquire(ctx, "charlie", limits)
	if err != nil {
		t.Fatal(err)
	}

	release()
	release() // Should not panic or decrement below zero.

	// Should be able to acquire again.
	release2, err := tracker.Acquire(ctx, "charlie", limits)
	if err != nil {
		t.Fatalf("expected success after double release: %v", err)
	}
	release2()
}

func TestTracker_DifferentUsersIndependent(t *testing.T) {
	tracker, _ := setupTracker(t)
	ctx := context.Background()
	limits := auth.MergedLimits{MaxConns: 1}

	release1, err := tracker.Acquire(ctx, "alice", limits)
	if err != nil {
		t.Fatal(err)
	}
	defer release1()

	// Different user should not be blocked.
	release2, err := tracker.Acquire(ctx, "bob", limits)
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
}

func TestTracker_WrapConn_Deadline(t *testing.T) {
	tracker, _ := setupTracker(t)
	ctx := context.Background()
	limits := auth.MergedLimits{MaxConnDuration: 50 * time.Millisecond}

	cl := tracker.WrapConn(ctx, "alice", limits)
	if cl.deadline.IsZero() {
		t.Fatal("expected non-zero deadline")
	}

	// Should not be expired yet.
	if err := cl.ReportBytes(0); err != nil {
		t.Fatalf("unexpected error before deadline: %v", err)
	}

	time.Sleep(60 * time.Millisecond)

	if err := cl.ReportBytes(0); err != errDeadlineExceeded {
		t.Fatalf("expected deadline exceeded, got: %v", err)
	}
}

func TestTracker_WrapConn_NoDeadline(t *testing.T) {
	tracker, _ := setupTracker(t)
	ctx := context.Background()
	limits := auth.MergedLimits{}

	cl := tracker.WrapConn(ctx, "alice", limits)
	if !cl.deadline.IsZero() {
		t.Fatal("expected zero deadline for no duration limit")
	}
}
