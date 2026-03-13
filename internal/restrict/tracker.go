package restrict

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
)

// Tracker orchestrates per-connection (local) and per-user (Redis) limits.
type Tracker struct {
	store   *RedisStore
	metrics *metrics.Metrics
	logger  *slog.Logger
}

// NewTracker creates a new limit tracker.
func NewTracker(store *RedisStore, m *metrics.Metrics, logger *slog.Logger) *Tracker {
	return &Tracker{store: store, metrics: m, logger: logger}
}

// Acquire checks and increments the connection count for a user.
// Returns a release function that must be called when the connection closes.
func (t *Tracker) Acquire(ctx context.Context, user string, limits auth.MergedLimits) (func(), error) {
	if limits.MaxConns > 0 {
		current, err := t.store.GetConns(ctx, user)
		if err != nil {
			return nil, fmt.Errorf("check conn count: %w", err)
		}
		if current >= int64(limits.MaxConns) {
			t.metrics.LimitViolations.Add(ctx, 1,
				t.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("max_conns")))
			return nil, fmt.Errorf("connection limit exceeded (%d/%d)", current, limits.MaxConns)
		}
	}

	count, err := t.store.IncrConns(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("increment conn count: %w", err)
	}

	// Double-check after increment (race window is acceptable per spec).
	if limits.MaxConns > 0 && count > int64(limits.MaxConns) {
		t.store.DecrConns(ctx, user)
		t.metrics.LimitViolations.Add(ctx, 1,
			t.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("max_conns")))
		return nil, fmt.Errorf("connection limit exceeded (%d/%d)", count, limits.MaxConns)
	}

	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if err := t.store.DecrConns(context.Background(), user); err != nil {
			t.logger.Error("failed to release connection count", "user", user, "error", err)
		}
	}

	return release, nil
}

// WrapConn wraps a net.Conn with byte counting and limit enforcement.
func (t *Tracker) WrapConn(ctx context.Context, user string, limits auth.MergedLimits) *ConnLimits {
	cl := &ConnLimits{
		store:           t.store,
		metrics:         t.metrics,
		user:            user,
		maxBytesPerConn: limits.MaxBytesPerConn,
		bandwidthTiers:  limits.BandwidthTiers,
		logger:          t.logger,
		flushInterval:   10 * time.Second,
	}

	if limits.MaxConnDuration > 0 {
		cl.deadline = time.Now().Add(limits.MaxConnDuration)
	}

	return cl
}
