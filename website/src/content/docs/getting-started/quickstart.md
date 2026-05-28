---
title: Quickstart
description: Stand up a Postgres listener end-to-end.
sidebar:
  order: 2
---

This walks through the smallest useful Waypoint deployment: one Postgres backend, one tailnet, one user.

## 1. Tag a node for Waypoint

In the Tailscale admin console, define an ACL tag (e.g. `tag:waypoint`) with yourself as an owner, and mint an auth key tagged with it. Export the key:

```sh
export TS_AUTHKEY=tskey-auth-...
```

## 2. Run Redis

Anywhere reachable from the Waypoint node:

```sh
docker run -d -p 6379:6379 redis:7
```

If you use the devenv shell, `devenv up` starts a local Redis automatically.

## 3. Create admin credentials on the backend

On the Postgres backend, create a role Waypoint can use to provision per-user roles:

```sql
CREATE ROLE waypoint_admin WITH LOGIN PASSWORD '...' CREATEROLE;
```

`CREATEROLE` is the minimum privilege needed. Waypoint also needs `CONNECT` on every database it will provision against.

## 4. Write `waypoint.toml`

```toml
[tailscale]
hostname = "waypoint-db"
state_dir = "/var/lib/waypoint/tsnet"

[redis]
address = "localhost:6379"
key_prefix = "waypoint:"

[revalidation]
interval = "1m"

[[listeners]]
name = "pg-main"
listen = ":5432"
mode = "postgres"
backend = "10.0.1.10:5432"
tls_mode = "optional"

[listeners.postgres]
admin_user = "waypoint_admin"
admin_password = "${PG_ADMIN_PASSWORD}"
admin_database = "postgres"
user_prefix = "wp_"
user_ttl = "24h"
```

`${VAR}` is expanded from the process environment at startup.

## 5. Add an ACL grant

In your Tailscale ACL policy:

```json
{
  "grants": [{
    "src": ["autogroup:member"],
    "dst": ["tag:waypoint"],
    "cap": {
      "redo.com/cap/waypoint": [{
        "backends": {
          "pg-main": {
            "pg": {
              "databases": {
                "myapp": { "permissions": ["readwrite"] }
              }
            }
          }
        }
      }]
    }
  }]
}
```

## 6. Start Waypoint

```sh
waypoint -config waypoint.toml
```

## 7. Connect

Any Postgres client on the tailnet. Username and password are ignored — identity comes from Tailscale:

```sh
psql "postgres://ignored:ignored@waypoint-db/myapp?sslmode=require"
```

To request a lower preset for one connection, add `waypoint_presets=readonly`. See [Capability Grants](/waypoint/acl/capability-grants/) for the full grant schema.
