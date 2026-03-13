package metrics

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Attribute key constants for metric tagging.
var (
	AttrListener  = attribute.Key("listener")
	AttrUser      = attribute.Key("user")
	AttrMode      = attribute.Key("mode")
	AttrBackend   = attribute.Key("backend")
	AttrErrorType = attribute.Key("error_type")
	AttrLimitType = attribute.Key("limit_type")
	AttrDirection = attribute.Key("direction")
	AttrDatabase  = attribute.Key("database")
	AttrOperation = attribute.Key("operation")
)

// Attrs filters attributes for the given metric, keeping only tags in that
// metric's allow-list (or all if "*"). Returns a MeasurementOption.
func (m *Metrics) Attrs(metricName string, kvs ...attribute.KeyValue) metric.MeasurementOption {
	allowed, ok := m.tagSets[metricName]
	if !ok {
		// Metric not in config — return empty set.
		return metric.WithAttributeSet(attribute.NewSet())
	}

	// Wildcard: keep all attributes.
	if allowed == nil {
		return metric.WithAttributeSet(attribute.NewSet(kvs...))
	}

	filtered := make([]attribute.KeyValue, 0, len(kvs))
	for _, kv := range kvs {
		if allowed[string(kv.Key)] {
			filtered = append(filtered, kv)
		}
	}
	return metric.WithAttributeSet(attribute.NewSet(filtered...))
}
