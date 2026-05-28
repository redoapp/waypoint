---
title: Metrics
description: OpenTelemetry metrics with opt-in per-name enrollment.
sidebar:
  order: 1
---

Waypoint emits OpenTelemetry metrics over OTLP to any compatible collector.

```toml
[metrics]
endpoint = "http://otel-collector:4318"
protocol = "http"          # "http" (default) or "grpc"
interval = "30s"
temporality = "delta"      # "delta" (default, recommended for Datadog) or "cumulative"

[metrics.enable]
"waypoint.conn.active"   = ["listener", "mode"]
"waypoint.conn.total"    = ["listener", "mode"]
"waypoint.auth.attempts" = ["listener"]
"waypoint.bytes.read"    = ["listener", "user"]
"waypoint.bytes.written" = ["listener", "user"]
```

## Per-metric opt-in

Metrics are emitted only when explicitly listed under `[metrics.enable]`. The key is the metric name; the value is a **tag allow-list**:

- `["listener", "mode"]` — only these tags are attached.
- `["*"]` — all available tags.
- `[]` — no tags (the metric is a single scalar).

This makes cardinality predictable: a metric like `waypoint.bytes.read` tagged by `user` will produce one time series per user; if that's too many, narrow the tag list to `["listener"]`.

## Available metrics

| Metric | Type | Tags |
|---|---|---|
| `waypoint.conn.active` | gauge | `listener`, `mode`, `backend` |
| `waypoint.conn.total` | counter | `listener`, `mode` |
| `waypoint.conn.duration` | histogram | `listener`, `user`, `backend` |
| `waypoint.conn.rejected` | counter | `listener`, `mode` |
| `waypoint.auth.attempts` | counter | `listener` |
| `waypoint.auth.failures` | counter | `listener` |
| `waypoint.auth.latency` | histogram | `listener`, `backend` |
| `waypoint.reval.attempts` | counter | `listener` |
| `waypoint.reval.failures` | counter | `listener` |
| `waypoint.bytes.read` | counter | `listener`, `user` |
| `waypoint.bytes.written` | counter | `listener`, `user` |
| `waypoint.limit.violations` | counter | `listener`, `limit_type` |
| `waypoint.provision.total` | counter | `listener` |
| `waypoint.provision.latency` | histogram | `listener` |
| `waypoint.provision.errors` | counter | `listener` |
| `waypoint.cleanup.runs` | counter | — |
| `waypoint.cleanup.dropped` | counter | — |
| `waypoint.redis.op_duration` | histogram | `operation` |
| `waypoint.redis.errors` | counter | `operation` |
| `waypoint.system.listeners` | gauge | — |

## Temporality

Default is `delta` because Datadog and most modern collectors prefer it for counters and histograms. Use `cumulative` if your backend (e.g. Prometheus) wants monotonic counters.

## Endpoint

`endpoint` is required to enable any metrics export — without it, nothing is sent regardless of `[metrics.enable]` contents.
