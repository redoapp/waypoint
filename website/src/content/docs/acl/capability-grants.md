---
title: Capability Grants
description: The redo.com/cap/waypoint capability schema.
sidebar:
  order: 1
---

Access to Waypoint is controlled entirely by Tailscale ACL capability grants under the name `redo.com/cap/waypoint`. There are no users, no roles, and no permissions stored in Waypoint itself — every authorization decision is read from the ACL on each connection.

## Shape

```json
{
  "grants": [{
    "src": ["group:backend"],
    "dst": ["tag:waypoint"],
    "cap": {
      "redo.com/cap/waypoint": [{
        "limits":   { /* optional per-user limits */ },
        "backends": { /* per-listener grants */ }
      }]
    }
  }]
}
```

`src` and `dst` are standard Tailscale ACL fields. The capability payload is an **array** of objects; if multiple grants match, Waypoint takes the most permissive intersection of `backends` and the strictest values from `limits`.

## `limits`

| Field | Meaning |
|---|---|
| `max_conns` | Concurrent connections per user |
| `max_conn_duration` | Hard ceiling on a single connection's lifetime |
| `max_bytes_per_conn` | Byte budget per connection (e.g. `"10GB"`) |

Missing fields fall back to `[defaults.limits]` from the server config. See [Provisioning & Defaults](/waypoint/configuration/provisioning/).

## `backends`

Map keyed by listener `name`. Empty objects mean "allowed with no per-protocol detail" (the right shape for [TCP](/waypoint/listeners/tcp/) listeners).

For Postgres:

```json
{
  "backends": {
    "pg-main": {
      "pg": {
        "databases": {
          "myapp": {
            "permissions": ["readwrite"],
            "schemas": ["public", "app"]
          },
          "*": { "permissions": ["readonly"] }
        }
      }
    }
  }
}
```

The `databases` map keys are database names; `*` matches anything not listed explicitly. Each entry has:

- `permissions` — array of preset names (see below).
- `schemas` — schemas to apply the presets to. Defaults to `["public"]`.
- `sql` — optional raw SQL templates. See [Raw SQL](/waypoint/acl/raw-sql/).

## Presets

| Preset | Grants |
|---|---|
| `readonly` | `USAGE` on schema; `SELECT` on all tables and sequences |
| `readwrite` | Everything in `readonly` + `INSERT`, `UPDATE`, `DELETE` on tables, `USAGE` on sequences |
| `admin` | `ALL PRIVILEGES` on tables and sequences; `USAGE` + `CREATE` on schema |

For MongoDB, presets map to MongoDB built-in roles (`read`, `readWrite`, `dbAdmin`). See [MongoDB](/waypoint/listeners/mongodb/) for the static-user matching rules when `provision.mode = "static"`.

## Per-connection downgrade

Postgres clients can downgrade their effective preset for one connection with `?waypoint_presets=readonly` in the connection string. This **cannot elevate** beyond the grant; it only narrows. See [Postgres](/waypoint/listeners/postgres/#per-connection-preset-override).
