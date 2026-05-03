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

// Acquire checks and increments the connection count for a user,
// enforcing both per-user (global) and per-endpoint limits.
// Returns a release function that must be called when the connection closes.
func (t *Tracker) Acquire(ctx context.Context, user string, limits auth.MergedLimits, listenerName string) (func(), error) {
	// Check per-endpoint limit (leaf key).
	if limits.Endpoint != nil && limits.Endpoint.MaxConns > 0 {
		current, err := t.store.GetConns(ctx, user, listenerName)
		if err != nil {
			return nil, fmt.Errorf("check endpoint conn count: %w", err)
		}
		if current >= int64(limits.Endpoint.MaxConns) {
			t.metrics.LimitViolations.Add(ctx, 1,
				t.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("endpoint_max_conns")))
			return nil, fmt.Errorf("endpoint connection limit exceeded (%d/%d)", current, limits.Endpoint.MaxConns)
		}
	}

	// Check per-user (global) limit (root key).
	if limits.MaxConns > 0 {
		current, err := t.store.GetConns(ctx, user, "")
		if err != nil {
			return nil, fmt.Errorf("check global conn count: %w", err)
		}
		if current >= int64(limits.MaxConns) {
			t.metrics.LimitViolations.Add(ctx, 1,
				t.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("max_conns")))
			return nil, fmt.Errorf("connection limit exceeded (%d/%d)", current, limits.MaxConns)
		}
	}

	// Hierarchical increment — bumps leaf + root atomically.
	count, err := t.store.IncrConns(ctx, user, listenerName)
	if err != nil {
		return nil, fmt.Errorf("increment conn count: %w", err)
	}
	t.logger.Debug("connection acquired", "user", user, "listener", listenerName, "count", count)

	// Double-check after increment (race window is acceptable per spec).
	if limits.Endpoint != nil && limits.Endpoint.MaxConns > 0 && count > int64(limits.Endpoint.MaxConns) {
		t.store.DecrConns(ctx, user, listenerName)
		t.metrics.LimitViolations.Add(ctx, 1,
			t.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("endpoint_max_conns")))
		return nil, fmt.Errorf("endpoint connection limit exceeded (%d/%d)", count, limits.Endpoint.MaxConns)
	}
	if limits.MaxConns > 0 {
		globalCount, err := t.store.GetConns(ctx, user, "")
		if err == nil && globalCount > int64(limits.MaxConns) {
			t.store.DecrConns(ctx, user, listenerName)
			t.metrics.LimitViolations.Add(ctx, 1,
				t.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("max_conns")))
			return nil, fmt.Errorf("connection limit exceeded (%d/%d)", globalCount, limits.MaxConns)
		}
	}

	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if err := t.store.DecrConns(context.Background(), user, listenerName); err != nil {
			t.logger.Error("failed to release connection count", "user", user, "listener", listenerName, "error", err)
		}
	}

	return release, nil
}

// WrapConn wraps a net.Conn with byte counting and limit enforcement.
func (t *Tracker) WrapConn(ctx context.Context, user string, limits auth.MergedLimits, listenerName string) *ConnLimits {
	// Use the more restrictive of global and endpoint limits for per-conn values.
	maxBytesPerConn := limits.MaxBytesPerConn
	if limits.Endpoint != nil && limits.Endpoint.MaxBytesPerConn > 0 {
		if maxBytesPerConn == 0 || limits.Endpoint.MaxBytesPerConn < maxBytesPerConn {
			maxBytesPerConn = limits.Endpoint.MaxBytesPerConn
		}
	}

	maxConnDuration := limits.MaxConnDuration
	if limits.Endpoint != nil && limits.Endpoint.MaxConnDuration > 0 {
		if maxConnDuration == 0 || limits.Endpoint.MaxConnDuration < maxConnDuration {
			maxConnDuration = limits.Endpoint.MaxConnDuration
		}
	}

	// Merge bandwidth tiers: use global tiers + endpoint tiers.
	// For the same period, keep the most restrictive.
	bandwidthTiers := append([]auth.BandwidthTier{}, limits.BandwidthTiers...)
	if limits.Endpoint != nil {
		for _, epTier := range limits.Endpoint.BandwidthTiers {
			found := false
			for i := range bandwidthTiers {
				if bandwidthTiers[i].Period == epTier.Period {
					if epTier.Bytes < bandwidthTiers[i].Bytes {
						bandwidthTiers[i].Bytes = epTier.Bytes
					}
					found = true
					break
				}
			}
			if !found {
				bandwidthTiers = append(bandwidthTiers, epTier)
			}
		}
	}

	cl := &ConnLimits{
		store:           t.store,
		metrics:         t.metrics,
		user:            user,
		scope:           listenerName,
		maxBytesPerConn: maxBytesPerConn,
		bandwidthTiers:  bandwidthTiers,
		logger:          t.logger,
		flushInterval:   10 * time.Second,
		listenerAttr:    metrics.AttrListener.String(listenerName),
	}

	if maxConnDuration > 0 {
		cl.deadline = time.Now().Add(maxConnDuration)
	}

	return cl
}
