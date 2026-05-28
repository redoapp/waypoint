---
title: Redis
description: Connection tracking, distributed locks, and heartbeat storage.
sidebar:
  order: 3
---

Waypoint stores all cross-instance coordination state in Redis (or Valkey):

- Per-user concurrent-connection counts and byte budgets.
- Distributed locks for role provisioning (so two Waypoint instances don't race to create the same backend user).
- Heartbeat records that `waypoint-monitor` uses to discover instances.

```toml
[redis]
address = "localhost:6379"
# password = ""
# db = 0
key_prefix = "waypoint:"
# service_name = "redis"
```

## address

`host:port`. Required.

## password / db

Optional. Use `password` for AUTH-protected instances; `db` selects a logical database (default `0`).

## key_prefix

Every key Waypoint writes is prefixed with this string. Pick something distinctive so you can run multiple Waypoint deployments against one Redis instance without collisions, and so you can `KEYS waypoint:*` for debugging.

## service_name

Sets the `peer.service` attribute on Redis spans in OpenTelemetry traces. Default is `redis`. Override if you have multiple Redis backends you want to distinguish in tracing UIs.

## Reliability

Waypoint treats Redis as a hard dependency for authorization decisions. If Redis is unreachable, new connections fail closed (rejected) — the proxy will not silently drop limit enforcement. Existing connections continue until the next revalidation tick.

For HA, point Waypoint at a Sentinel-fronted or clustered Redis. The client (`github.com/redis/go-redis/v9`) follows redirects and reconnects automatically.
