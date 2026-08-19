package provision

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
)

func lockTestStore(t *testing.T) *restrict.RedisStore {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return restrict.NewRedisStore(rdb, "test:", metrics.Noop())
}

func TestAcquireRoleLock_NilStore(t *testing.T) {
	release, err := acquireRoleLock(context.Background(), nil, "role:x", time.Second)
	if err != nil {
		t.Fatalf("nil store should not error: %v", err)
	}
	release()
}

func TestAcquireRoleLock_Uncontended(t *testing.T) {
	store := lockTestStore(t)

	release, err := acquireRoleLock(context.Background(), store, "role:x", time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()

	// Releasing must make the lock available again.
	release2, err := acquireRoleLock(context.Background(), store, "role:x", time.Second)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	release2()
}

func TestAcquireRoleLock_BusyReturnsErrLockBusy(t *testing.T) {
	store := lockTestStore(t)

	release, err := acquireRoleLock(context.Background(), store, "role:x", time.Second)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	start := time.Now()
	_, err = acquireRoleLock(context.Background(), store, "role:x", 300*time.Millisecond)
	if !errors.Is(err, ErrLockBusy) {
		t.Fatalf("want ErrLockBusy, got %v", err)
	}
	// It must actually have waited out the budget rather than the old
	// behaviour of bailing out after a fixed handful of retries.
	if waited := time.Since(start); waited < 250*time.Millisecond {
		t.Fatalf("gave up after %v, want it to wait out the ~300ms budget", waited)
	}
}

func TestAcquireRoleLock_WaiterProceedsAfterRelease(t *testing.T) {
	store := lockTestStore(t)

	release, err := acquireRoleLock(context.Background(), store, "role:x", time.Second)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		r, err := acquireRoleLock(context.Background(), store, "role:x", 5*time.Second)
		if err == nil {
			r()
		}
		done <- err
	}()

	// Hold briefly, then release: the waiter should pick it up, not time out.
	time.Sleep(150 * time.Millisecond)
	release()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waiter failed to acquire after release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiter never acquired the lock after it was released")
	}
}

func TestAcquireRoleLock_HonorsContextCancellation(t *testing.T) {
	store := lockTestStore(t)

	release, err := acquireRoleLock(context.Background(), store, "role:x", time.Second)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = acquireRoleLock(ctx, store, "role:x", 10*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestAcquireRoleLock_BudgetCappedByContextDeadline(t *testing.T) {
	store := lockTestStore(t)

	release, err := acquireRoleLock(context.Background(), store, "role:x", time.Second)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := acquireRoleLock(ctx, store, "role:x", time.Hour); err == nil {
		t.Fatal("expected an error when the context deadline precedes the budget")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("waited %v, should have stopped at the context deadline", waited)
	}
}

func TestJitterStaysInRange(t *testing.T) {
	const d = 100 * time.Millisecond
	for range 100 {
		got := jitter(d)
		if got < d/2 || got >= d+d/2 {
			t.Fatalf("jitter(%v) = %v, outside [%v, %v)", d, got, d/2, d+d/2)
		}
	}
}
