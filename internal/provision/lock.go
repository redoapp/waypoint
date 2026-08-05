package provision

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/redoapp/waypoint/internal/restrict"
)

// ErrLockBusy is returned when a role lock could not be taken within the
// caller's budget. It means another connection is provisioning the same role,
// not that the backend is broken, so callers can surface a retryable error.
var ErrLockBusy = errors.New("role busy: another connection is provisioning it")

// Lock wait tuning. A client opening a burst of connections has every one of
// them contend for the same role lock. The old fixed 10x100ms gave up after
// ~1s — well short of a single provisioning round — so all but the winner
// failed. Waiting long enough to cover a full round turns those failures into
// a slightly slower connect instead.
const (
	roleLockTTL = 30 * time.Second

	// lockAttemptBudget bounds one attempt at taking the role lock. On
	// expiry the caller pauses and starts a fresh provisioning round rather
	// than failing the connection; see lockBusyRetryDelay.
	lockAttemptBudget = 5 * time.Second

	// lockTotalBudget bounds every attempt made on behalf of one connection.
	// Past this the client has waited long enough that a retryable error
	// beats hanging further.
	lockTotalBudget = 20 * time.Second

	// lockBusyRetryDelay is the pause between attempts when another
	// connection holds the lock.
	lockBusyRetryDelay = 1 * time.Second

	lockRetryMin  = 50 * time.Millisecond
	lockRetryMax  = 1 * time.Second
	lockRetryGrow = 1.6
)

// acquireRoleLock takes the named distributed lock, retrying with exponential
// backoff and jitter until the budget expires or ctx is done. The returned
// release function is a no-op-safe single call; it is nil when err != nil.
// A nil store (locking disabled) yields a no-op release.
func acquireRoleLock(ctx context.Context, store *restrict.RedisStore, name string, budget time.Duration) (func(), error) {
	if store == nil {
		return func() {}, nil
	}
	if budget <= 0 {
		budget = lockAttemptBudget
	}

	deadline := time.Now().Add(budget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	delay := lockRetryMin
	for {
		token, err := store.AcquireLock(ctx, name, roleLockTTL)
		if err != nil {
			return nil, fmt.Errorf("acquire lock: %w", err)
		}
		if token != "" {
			return func() {
				// Release even when the caller's context is already cancelled:
				// abandoning the lock would stall every waiter for its full TTL.
				_ = store.ReleaseLock(context.WithoutCancel(ctx), name, token)
			}, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("%w (%s)", ErrLockBusy, name)
		}
		wait := min(jitter(delay), remaining)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}

		delay = min(time.Duration(float64(delay)*lockRetryGrow), lockRetryMax)
	}
}

// jitter spreads retries over [d/2, 3d/2) so a burst of waiters released at
// the same moment doesn't stampede the lock in lockstep.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d)))
}
