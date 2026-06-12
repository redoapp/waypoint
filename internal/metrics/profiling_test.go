package metrics

import (
	"io"
	"log/slog"
	"testing"
)

// When DD_PROFILING_ENABLED is unset/false, StartProfiling is a no-op: it
// returns a callable stop function and no error, and never starts the profiler.
func TestStartProfilingDisabledByDefault(t *testing.T) {
	t.Setenv("DD_PROFILING_ENABLED", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	stop, err := StartProfiling(logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stop == nil {
		t.Fatal("stop function must never be nil")
	}
	stop() // must be safe to call when profiling was never started
}

func TestStartProfilingDisabledExplicit(t *testing.T) {
	t.Setenv("DD_PROFILING_ENABLED", "false")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	stop, err := StartProfiling(logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stop()
}
