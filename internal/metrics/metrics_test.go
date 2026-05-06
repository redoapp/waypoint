package metrics

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestNoop_NoError(t *testing.T) {
	m := Noop()
	if m == nil {
		t.Fatal("Noop returned nil")
	}
	// Should be safe to call instruments on noop.
	ctx := context.Background()
	m.ConnTotal.Add(ctx, 1)
	m.ConnActive.Add(ctx, 1)
	m.ConnDuration.Record(ctx, 1.5)
	m.AuthAttempts.Add(ctx, 1)
	m.AuthLatency.Record(ctx, 0.5)
	m.BytesRead.Add(ctx, 100)
	m.LimitViolations.Add(ctx, 1)
	m.RedisOpDuration.Record(ctx, 0.01)
}

func TestNoop_Shutdown(t *testing.T) {
	m := Noop()
	if err := m.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown error: %v", err)
	}
}

func TestConfig_Defaults(t *testing.T) {
	c := Config{}
	if c.IntervalDuration().Seconds() != 30 {
		t.Errorf("expected 30s default interval, got %v", c.IntervalDuration())
	}
	if c.IsMetricEnabled("waypoint.conn.total") {
		t.Error("expected metric disabled with nil Enable map")
	}
	if c.TagsForMetric("waypoint.conn.total") != nil {
		t.Error("expected nil tags with nil Enable map")
	}
}

func TestConfig_IsMetricEnabled(t *testing.T) {
	c := Config{
		Enable: map[string][]string{
			"waypoint.conn.total": {"listener", "mode"},
		},
	}
	if !c.IsMetricEnabled("waypoint.conn.total") {
		t.Error("expected conn.total to be enabled")
	}
	if c.IsMetricEnabled("waypoint.conn.active") {
		t.Error("expected conn.active to be disabled")
	}
}

func TestConfig_TagsForMetric(t *testing.T) {
	c := Config{
		Enable: map[string][]string{
			"waypoint.conn.total": {"listener", "mode"},
		},
	}
	tags := c.TagsForMetric("waypoint.conn.total")
	if len(tags) != 2 || tags[0] != "listener" || tags[1] != "mode" {
		t.Errorf("unexpected tags: %v", tags)
	}
}

func TestConfig_IntervalDuration(t *testing.T) {
	c := Config{Interval: "10s"}
	if c.IntervalDuration().Seconds() != 10 {
		t.Errorf("expected 10s, got %v", c.IntervalDuration())
	}
	c2 := Config{Interval: "invalid"}
	if c2.IntervalDuration().Seconds() != 30 {
		t.Errorf("expected 30s default for invalid, got %v", c2.IntervalDuration())
	}
}

func TestConfig_TemporalitySelector(t *testing.T) {
	tests := []struct {
		name        string
		temporality string
		counterWant metricdata.Temporality
		upDownWant  metricdata.Temporality
		wantErr     bool
	}{
		{
			name:        "default delta",
			counterWant: metricdata.DeltaTemporality,
			upDownWant:  metricdata.CumulativeTemporality,
		},
		{
			name:        "explicit delta",
			temporality: "delta",
			counterWant: metricdata.DeltaTemporality,
			upDownWant:  metricdata.CumulativeTemporality,
		},
		{
			name:        "explicit cumulative",
			temporality: "cumulative",
			counterWant: metricdata.CumulativeTemporality,
			upDownWant:  metricdata.CumulativeTemporality,
		},
		{
			name:        "invalid",
			temporality: "rate",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector, err := (Config{Temporality: tt.temporality}).TemporalitySelector()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := selector(sdkmetric.InstrumentKindCounter); got != tt.counterWant {
				t.Errorf("counter temporality = %v, want %v", got, tt.counterWant)
			}
			if got := selector(sdkmetric.InstrumentKindUpDownCounter); got != tt.upDownWant {
				t.Errorf("updown temporality = %v, want %v", got, tt.upDownWant)
			}
		})
	}
}

func TestNonEnabledMetrics_UseNoop(t *testing.T) {
	// Only enable conn.total — conn.active should be noop.
	cfg := Config{
		Enable: map[string][]string{
			"waypoint.conn.total": {"listener"},
		},
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())

	m, err := NewWithProvider(provider, cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Record on enabled metric.
	m.ConnTotal.Add(ctx, 5, m.Attrs("waypoint.conn.total", AttrListener.String("pg-main")))
	// Record on non-enabled metric (should be noop).
	m.ConnActive.Add(ctx, 3, m.Attrs("waypoint.conn.active", AttrListener.String("pg-main")))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}

	// Should find conn.total but not conn.active.
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, met := range sm.Metrics {
			if met.Name == "waypoint.conn.total" {
				found = true
			}
			if met.Name == "waypoint.conn.active" {
				t.Error("conn.active should not appear in SDK metrics (should be noop)")
			}
		}
	}
	if !found {
		t.Error("conn.total should appear in SDK metrics")
	}
}

func TestEnabledMetrics_Record(t *testing.T) {
	cfg := Config{
		Enable: map[string][]string{
			"waypoint.conn.total":    {"listener", "mode"},
			"waypoint.auth.attempts": {"listener"},
		},
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())

	m, err := NewWithProvider(provider, cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	m.ConnTotal.Add(ctx, 1, m.Attrs("waypoint.conn.total",
		AttrListener.String("pg-main"), AttrMode.String("postgres")))
	m.AuthAttempts.Add(ctx, 1, m.Attrs("waypoint.auth.attempts",
		AttrListener.String("pg-main")))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}

	names := make(map[string]bool)
	for _, sm := range rm.ScopeMetrics {
		for _, met := range sm.Metrics {
			names[met.Name] = true
		}
	}
	if !names["waypoint.conn.total"] {
		t.Error("expected conn.total in metrics")
	}
	if !names["waypoint.auth.attempts"] {
		t.Error("expected auth.attempts in metrics")
	}
}

func TestAttrs_FiltersTags(t *testing.T) {
	cfg := Config{
		Enable: map[string][]string{
			"waypoint.conn.total": {"listener", "mode"},
		},
	}
	m, _ := NewWithProvider(noop.NewMeterProvider(), cfg)

	opt := m.Attrs("waypoint.conn.total",
		AttrListener.String("pg-main"),
		AttrMode.String("postgres"),
		AttrUser.String("alice"), // should be filtered out
	)
	if opt == nil {
		t.Fatal("expected non-nil option")
	}
}

func TestAttrs_Wildcard(t *testing.T) {
	cfg := Config{
		Enable: map[string][]string{
			"waypoint.conn.total": {"*"},
		},
	}
	m, _ := NewWithProvider(noop.NewMeterProvider(), cfg)

	// With wildcard, all tags should pass through.
	opt := m.Attrs("waypoint.conn.total",
		AttrListener.String("pg-main"),
		AttrUser.String("alice"),
		AttrBackend.String("db1"),
	)
	if opt == nil {
		t.Fatal("expected non-nil option")
	}
}

func TestAttrs_UnknownMetric(t *testing.T) {
	cfg := Config{
		Enable: map[string][]string{
			"waypoint.conn.total": {"listener"},
		},
	}
	m, _ := NewWithProvider(noop.NewMeterProvider(), cfg)

	// Unknown metric should return empty attribute set.
	opt := m.Attrs("waypoint.nonexistent",
		AttrListener.String("pg-main"),
	)
	if opt == nil {
		t.Fatal("expected non-nil option")
	}
}

func TestAttrs_EmptyTagList(t *testing.T) {
	cfg := Config{
		Enable: map[string][]string{
			"waypoint.conn.total": {}, // no tags allowed
		},
	}
	m, _ := NewWithProvider(noop.NewMeterProvider(), cfg)

	opt := m.Attrs("waypoint.conn.total",
		AttrListener.String("pg-main"),
		AttrMode.String("tcp"),
	)
	if opt == nil {
		t.Fatal("expected non-nil option")
	}
}

func TestAttrs_FilterVerification(t *testing.T) {
	// Use real SDK to verify tag filtering produces correct attribute sets.
	cfg := Config{
		Enable: map[string][]string{
			"waypoint.conn.total": {"listener"},
		},
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer provider.Shutdown(context.Background())

	m, err := NewWithProvider(provider, cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	m.ConnTotal.Add(ctx, 1, m.Attrs("waypoint.conn.total",
		AttrListener.String("pg-main"),
		AttrMode.String("postgres"), // should be filtered out
	))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}

	for _, sm := range rm.ScopeMetrics {
		for _, met := range sm.Metrics {
			if met.Name == "waypoint.conn.total" {
				sum, ok := met.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatal("expected Sum[int64]")
				}
				for _, dp := range sum.DataPoints {
					attrs := dp.Attributes
					// Should have listener but not mode.
					val, found := attrs.Value(attribute.Key("listener"))
					if !found || val.AsString() != "pg-main" {
						t.Errorf("expected listener=pg-main, got %v", val)
					}
					_, found = attrs.Value(attribute.Key("mode"))
					if found {
						t.Error("mode should have been filtered out")
					}
				}
			}
		}
	}
}
