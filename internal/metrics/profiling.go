package metrics

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/DataDog/dd-trace-go/v2/profiler"
)

// StartProfiling starts the Datadog continuous profiler when DD_PROFILING_ENABLED
// is truthy, and returns a stop function (always safe to call, even when
// profiling is disabled or failed to start).
//
// Service, environment, version, and the agent connection are read from the
// standard DD_* environment variables (DD_SERVICE, DD_ENV, DD_VERSION, and
// DD_AGENT_HOST / DD_TRACE_AGENT_URL). In the Kubernetes deployment these come
// from the pod's Datadog unified-tagging labels and the node-local agent host.
//
// Note: waypoint uses OpenTelemetry for tracing rather than the dd-trace-go
// tracer, so these profiles are NOT correlated with spans (no Code Hotspots /
// endpoint profiling). What this provides is the full set of Go runtime
// profiles — CPU, heap, goroutine, mutex, and block — which an out-of-process
// profiler cannot capture.
func StartProfiling(logger *slog.Logger) (stop func(), err error) {
	noop := func() {}

	if enabled, _ := strconv.ParseBool(os.Getenv("DD_PROFILING_ENABLED")); !enabled {
		return noop, nil
	}

	if err := profiler.Start(
		profiler.WithProfileTypes(
			profiler.CPUProfile,
			profiler.HeapProfile,
			profiler.GoroutineProfile,
			profiler.MutexProfile,
			profiler.BlockProfile,
		),
	); err != nil {
		return noop, fmt.Errorf("start datadog profiler: %w", err)
	}

	logger.Info("datadog continuous profiler started")
	return profiler.Stop, nil
}
