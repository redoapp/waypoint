---
title: Revalidation
description: Periodic mid-session identity re-checks.
sidebar:
  order: 5
---

Tailscale ACL grants can change at any time — users join and leave groups, capabilities are revoked, devices are removed. Waypoint re-evaluates identity for long-lived connections on a fixed interval.

```toml
[revalidation]
interval = "1m"
```

## What gets re-checked

Every `interval`, for every active connection:

1. `WhoIs` is called again on the source IP/port.
2. The caller's capability grants are re-evaluated against this listener and database.
3. For Postgres mode, the active backend role is **reconciled live** — `ReconcileRole` runs the necessary `GRANT` / `REVOKE` statements so the role's privileges match the current grant. The session is not dropped and its password is not rotated.

This means permission changes take effect mid-session: a user downgraded from `readwrite` to `readonly` keeps their existing connection but loses write privileges on the next tick.

## What happens when access is revoked

A *downgrade* (e.g. `readwrite` → `readonly`) is reconciled live and the session continues with reduced privileges. A *full revocation* of access to the connected database closes the connection.

| Revocation | Outcome |
|---|---|
| The caller has no `redo.com/cap/waypoint` grant at all anymore. | Connection closed. Logs `revalidation failed, closing connection`. |
| The caller still has the capability, but no grant references this listener. | Connection closed. Logs `revalidation failed, closing connection`. |
| The caller is still authorized for the listener, but the specific database they're connected to is no longer covered by any grant. | Role is reconciled with no privileges (defensive REVOKE), then the connection is closed. Logs `permissions revoked for this database, closing connection`. |
| `ReconcileRole` itself errors (backend unreachable, lock contention, etc.). | Connection closed. Logs `permission reconciliation failed, closing connection`. |

All four cases increment the `waypoint.reval.failures` counter, so a single metric is enough to alert on revocation events regardless of which path the revalidation took.

## Tuning

- `1m` is a reasonable default — fast enough to revoke access within a minute, infrequent enough to be invisible.
- For especially sensitive backends, drop to `15s` or `30s`.
- Setting `interval` to `0` disables revalidation entirely. This is rarely the right call — at minimum, the proxy still uses revalidation events as a heartbeat for byte-counter flushes.

## Trace correlation

Revalidation ticks emit linked spans rather than holding the original setup span open for the life of the connection. See [Tracing](/waypoint/observability/tracing/) for how to follow them.
