---
title: Postgres
description: Postgres-mode listener with dynamic per-user role provisioning.
sidebar:
  order: 1
---

Postgres mode intercepts the PostgreSQL wire protocol. For each incoming connection, Waypoint:

1. Authenticates the caller via Tailscale.
2. Reads the requested database from the startup message.
3. Provisions a temporary backend role with the permissions described by the ACL grant.
4. Authenticates as that role against the backend and proxies the rest of the session.

```toml
[[listeners]]
name = "pg-main"
listen = ":5432"
mode = "postgres"
backend = "10.0.1.10:5432"
tls_mode = "optional"
use_tailscale_tls = true

[listeners.postgres]
admin_user = "waypoint_admin"
admin_password = "${PG_ADMIN_PASSWORD}"
admin_database = "postgres"
user_prefix = "wp_"
user_ttl = "24h"
```

## Required fields

| Field | Purpose |
|---|---|
| `admin_user` / `admin_password` | Backend credentials Waypoint uses to create roles. Needs `CREATEROLE` plus `CONNECT` on each target database. |
| `admin_database` | Database to connect to for admin operations (usually `postgres`). |
| `user_prefix` | All provisioned roles begin with this string. Default `wp_`. |
| `user_ttl` | How long a role stays in the database after last use before cleanup eligibility. |

## How roles are named

Roles are deterministically named from the caller's identity and target database, e.g. `wp_alice_laptop_appdb`. This means the same user reconnecting reuses the same role (and its password is rotated each time), keeping the role count bounded.

## Per-connection preset override

Postgres clients can request a lower effective preset for one connection via the `waypoint_presets` query parameter:

```text
postgres://ignored:ignored@waypoint-db/myapp?sslmode=require&waypoint_presets=readonly
```

Values are `readonly`, `readwrite`, or `admin`. Comma-separated values are accepted; the strongest listed is treated as the maximum. The override **cannot elevate** beyond the ACL grant — a `readonly` grant stays read-only even if the client asks for `admin`.

When set, Waypoint provisions a scoped backend role for that effective preset and skips raw-SQL grants for that connection.

## TLS

Postgres clients negotiate TLS via `SSLRequest`. Waypoint serves the certificate that matches the requested server name. See [TLS](/waypoint/configuration/tls/) for the full certificate-selection logic. Use `tls_mode = "require"` to reject plaintext clients entirely.

## CockroachDB

Waypoint auto-detects CockroachDB backends and adjusts role-lifecycle behavior accordingly. See [CockroachDB](/waypoint/listeners/cockroachdb/) for the differences.
