---
title: Profiling
description: Datadog continuous profiling (CPU, heap, goroutine, mutex, block).
sidebar:
  order: 3
---

Waypoint can run the [Datadog continuous profiler](https://docs.datadoghq.com/profiler/) in-process via `dd-trace-go`. Unlike metrics and tracing, profiling is configured entirely through **environment variables**, not `waypoint.toml`.

## Enabling

Set `DD_PROFILING_ENABLED=true`. The profiler is otherwise a no-op with zero overhead.

```sh
DD_PROFILING_ENABLED=true
DD_SERVICE=waypoint-proxy
DD_ENV=production
DD_VERSION=0.6.7
DD_AGENT_HOST=10.0.0.1   # node-local Datadog agent (trace-agent intake, port 8126)
```

`DD_SERVICE`, `DD_ENV`, and `DD_VERSION` tag the profiles for Datadog's unified service tagging. The profiler uploads to the local Datadog agent, resolved from `DD_AGENT_HOST` (default port `8126`) or `DD_TRACE_AGENT_URL`. In Kubernetes these are wired from the pod's `tags.datadoghq.com/*` labels and the node's host IP.

If the profiler fails to start, waypoint logs a warning and continues — profiling never blocks the proxy.

## What gets profiled

The full set of Go runtime profiles:

- **CPU** — where on-CPU time is spent.
- **Heap** — allocations and in-use memory.
- **Goroutine** — goroutine counts and stacks.
- **Mutex** and **Block** — lock contention and blocking operations.

## No trace correlation

Waypoint traces with OpenTelemetry, not the `dd-trace-go` tracer, so profiles are **not** linked to spans — Datadog's Code Hotspots and endpoint profiling views are unavailable. The profiles are service-wide. This is the trade-off for keeping tracing on OTLP; the runtime profiles above are still fully captured (and are richer than any out-of-process profiler, which cannot see the Go heap, goroutines, or contention).
