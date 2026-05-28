---
title: Tracing
description: OTLP distributed tracing for connection setup, Redis ops, and revalidation.
sidebar:
  order: 2
---

Distributed tracing uses the same OTLP collector as metrics. Enable it by setting `tracing_sample_rate > 0` and providing a metrics `endpoint`.

```toml
[metrics]
endpoint = "http://otel-collector:4318"
tracing_sample_rate = 1.0   # 0 = disabled, 1.0 = trace all
```

## What gets traced

- **Connection setup** — auth (`WhoIs` + cap eval), Redis slot acquisition, backend dial, PG/Mongo provisioning.
- **Redis operations** — locks, counters, bandwidth bookkeeping.
- **Mid-session revalidation** — each revalidation tick is its own span linked to the original setup span.
- **Connection close** — final byte counts, total duration.

## Linked spans, not long-lived spans

Long-lived connections (think: a Postgres session held open for hours) don't keep one span open for the whole duration — that would produce unbounded spans and break most tracing backends. Instead:

1. The **setup span** ends as soon as the relay begins.
2. Revalidation ticks emit their own **child-of-setup-via-link** spans.
3. The **close span** is also linked back to the setup span.

This lets you reconstruct the full picture of a long connection in your tracing UI by following links from the setup trace, without holding any single span open.

## peer.service overrides

By default, the `peer.service` attribute on backend spans is the listener `name`. Override it per listener:

```toml
[listeners.postgres]
service_name = "my-prod-db"
```

For Redis, override the global `peer.service` from the `[redis]` section:

```toml
[redis]
service_name = "waypoint-redis"
```

## Sampling

`tracing_sample_rate` is parent-based head sampling. Set `1.0` in development; in production typically `0.01`–`0.1` is plenty unless you're actively debugging.
