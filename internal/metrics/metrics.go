package metrics

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Metrics holds all OTel instruments for waypoint.
type Metrics struct {
	provider metric.MeterProvider
	// sdkProvider is non-nil only when using a real (non-noop) provider,
	// so Shutdown can flush it.
	sdkProvider *sdkmetric.MeterProvider

	// tagSets is pre-computed from config: metric name → allowed tag keys.
	// nil map value means wildcard (all tags allowed).
	tagSets map[string]map[string]bool

	// Connection metrics.
	ConnActive   metric.Int64UpDownCounter
	ConnTotal    metric.Int64Counter
	ConnDuration metric.Float64Histogram
	ConnRejected metric.Int64Counter

	// Auth metrics.
	AuthAttempts metric.Int64Counter
	AuthFailures metric.Int64Counter
	AuthLatency  metric.Float64Histogram

	// Revalidation metrics.
	RevalAttempts metric.Int64Counter
	RevalFailures metric.Int64Counter

	// Byte metrics.
	BytesRead    metric.Int64Counter
	BytesWritten metric.Int64Counter

	// Limit metrics.
	LimitViolations metric.Int64Counter

	// Provision metrics.
	ProvisionTotal   metric.Int64Counter
	ProvisionLatency metric.Float64Histogram
	ProvisionErrors  metric.Int64Counter

	// Redis metrics.
	RedisOpDuration metric.Float64Histogram
	RedisErrors     metric.Int64Counter

	// System metrics.
	SystemListeners metric.Int64UpDownCounter
}

// Config mirrors the TOML [metrics] section.
type Config struct {
	Endpoint string              `toml:"endpoint"`
	Interval string              `toml:"interval"`
	Enable   map[string][]string `toml:"enable"`
}

// IntervalDuration parses the interval string. Defaults to 30s.
func (c Config) IntervalDuration() time.Duration {
	if c.Interval == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(c.Interval)
	if err != nil {
		return 30 * time.Second
	}
	return d
}

// IsMetricEnabled returns true if the metric name appears in the enable map.
func (c Config) IsMetricEnabled(name string) bool {
	if c.Enable == nil {
		return false
	}
	_, ok := c.Enable[name]
	return ok
}

// TagsForMetric returns the tag allow-list for a metric name.
func (c Config) TagsForMetric(name string) []string {
	if c.Enable == nil {
		return nil
	}
	return c.Enable[name]
}

// New creates a new Metrics instance. If cfg.Endpoint is empty, all instruments
// are noop (zero overhead). Only metrics listed in cfg.Enable are active.
func New(ctx context.Context, cfg Config) (*Metrics, error) {
	m := &Metrics{
		tagSets: buildTagSets(cfg),
	}

	if cfg.Endpoint == "" {
		m.provider = noop.NewMeterProvider()
		return m.init()
	}

	exporter, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(cfg.Endpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithInterval(cfg.IntervalDuration()),
	)

	m.sdkProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
	)
	m.provider = m.sdkProvider

	return m.init()
}

// NewWithProvider creates Metrics using an explicit MeterProvider (for testing).
func NewWithProvider(provider metric.MeterProvider, cfg Config) (*Metrics, error) {
	m := &Metrics{
		provider: provider,
		tagSets:  buildTagSets(cfg),
	}
	return m.init()
}

func (m *Metrics) init() (*Metrics, error) {
	noopMeter := noop.NewMeterProvider().Meter("noop")
	realMeter := m.provider.Meter("waypoint")

	meter := func(name string) metric.Meter {
		if m.tagSets == nil {
			return noopMeter
		}
		if _, ok := m.tagSets[name]; ok {
			return realMeter
		}
		return noopMeter
	}

	var err error

	if m.ConnActive, err = meter("waypoint.conn.active").Int64UpDownCounter("waypoint.conn.active"); err != nil {
		return nil, err
	}
	if m.ConnTotal, err = meter("waypoint.conn.total").Int64Counter("waypoint.conn.total"); err != nil {
		return nil, err
	}
	if m.ConnDuration, err = meter("waypoint.conn.duration").Float64Histogram("waypoint.conn.duration", metric.WithUnit("s")); err != nil {
		return nil, err
	}
	if m.ConnRejected, err = meter("waypoint.conn.rejected").Int64Counter("waypoint.conn.rejected"); err != nil {
		return nil, err
	}
	if m.AuthAttempts, err = meter("waypoint.auth.attempts").Int64Counter("waypoint.auth.attempts"); err != nil {
		return nil, err
	}
	if m.AuthFailures, err = meter("waypoint.auth.failures").Int64Counter("waypoint.auth.failures"); err != nil {
		return nil, err
	}
	if m.AuthLatency, err = meter("waypoint.auth.latency").Float64Histogram("waypoint.auth.latency", metric.WithUnit("s")); err != nil {
		return nil, err
	}
	if m.RevalAttempts, err = meter("waypoint.reval.attempts").Int64Counter("waypoint.reval.attempts"); err != nil {
		return nil, err
	}
	if m.RevalFailures, err = meter("waypoint.reval.failures").Int64Counter("waypoint.reval.failures"); err != nil {
		return nil, err
	}
	if m.BytesRead, err = meter("waypoint.bytes.read").Int64Counter("waypoint.bytes.read", metric.WithUnit("By")); err != nil {
		return nil, err
	}
	if m.BytesWritten, err = meter("waypoint.bytes.written").Int64Counter("waypoint.bytes.written", metric.WithUnit("By")); err != nil {
		return nil, err
	}
	if m.LimitViolations, err = meter("waypoint.limit.violations").Int64Counter("waypoint.limit.violations"); err != nil {
		return nil, err
	}
	if m.ProvisionTotal, err = meter("waypoint.provision.total").Int64Counter("waypoint.provision.total"); err != nil {
		return nil, err
	}
	if m.ProvisionLatency, err = meter("waypoint.provision.latency").Float64Histogram("waypoint.provision.latency", metric.WithUnit("s")); err != nil {
		return nil, err
	}
	if m.ProvisionErrors, err = meter("waypoint.provision.errors").Int64Counter("waypoint.provision.errors"); err != nil {
		return nil, err
	}
	if m.RedisOpDuration, err = meter("waypoint.redis.op_duration").Float64Histogram("waypoint.redis.op_duration", metric.WithUnit("s")); err != nil {
		return nil, err
	}
	if m.RedisErrors, err = meter("waypoint.redis.errors").Int64Counter("waypoint.redis.errors"); err != nil {
		return nil, err
	}
	if m.SystemListeners, err = meter("waypoint.system.listeners").Int64UpDownCounter("waypoint.system.listeners"); err != nil {
		return nil, err
	}

	return m, nil
}

// Shutdown flushes and shuts down the meter provider.
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m.sdkProvider != nil {
		return m.sdkProvider.Shutdown(ctx)
	}
	return nil
}

// Noop returns a Metrics instance with all noop instruments.
func Noop() *Metrics {
	m, _ := New(context.Background(), Config{})
	return m
}

func buildTagSets(cfg Config) map[string]map[string]bool {
	if cfg.Enable == nil {
		return nil
	}

	sets := make(map[string]map[string]bool, len(cfg.Enable))
	for name, tags := range cfg.Enable {
		if len(tags) == 1 && tags[0] == "*" {
			sets[name] = nil // nil means wildcard
		} else {
			allowed := make(map[string]bool, len(tags))
			for _, t := range tags {
				allowed[t] = true
			}
			sets[name] = allowed
		}
	}
	return sets
}
