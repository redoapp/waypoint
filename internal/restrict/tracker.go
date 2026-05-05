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
	endpointMaxConns := 0
	if limits.Endpoint != nil {
		endpointMaxConns = limits.Endpoint.MaxConns
	}

	leafCount, rootCount, decision, err := t.store.tryAcquireConns(ctx, user, listenerName, endpointMaxConns, limits.MaxConns)
	if err != nil {
		return nil, fmt.Errorf("increment conn count: %w", err)
	}

	switch decision {
	case connAcquireEndpointLimit:
		t.metrics.LimitViolations.Add(ctx, 1,
			t.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("endpoint_max_conns")))
		return nil, fmt.Errorf("endpoint connection limit exceeded (%d/%d)", leafCount, endpointMaxConns)
	case connAcquireGlobalLimit:
		t.metrics.LimitViolations.Add(ctx, 1,
			t.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("max_conns")))
		return nil, fmt.Errorf("connection limit exceeded (%d/%d)", rootCount, limits.MaxConns)
	case connAcquireOK:
		t.logger.DebugContext(ctx, "connection acquired", "user", user, "listener", listenerName, "count", leafCount)
	default:
		return nil, fmt.Errorf("unexpected connection acquire decision %d", decision)
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
