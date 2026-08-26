---
title: Provisioning & Defaults
description: allow_raw_sql gating and default per-user limits.
sidebar:
  order: 6
---

## What the admin role needs

Provisioning connects to the backend as `admin_user` and needs enough
privilege to manage roles and hand out grants:

- **`CREATEROLE`**, to create the per-user role and the preset group roles.
- **`CONNECT` on every database it provisions for.** Privileges on schemas,
  tables and sequences are stored per database in Postgres, so Waypoint
  connects to the database a role is being provisioned for in order to grant
  them there. `admin_database` is only the fallback used when the target does
  not exist.
- **The ability to grant what the presets ask for** — normally ownership of the
  schemas involved, or membership in a role that owns them.

A superuser satisfies all of this and is the simplest option for a backend
Waypoint fully manages. For a shared cluster, a non-superuser with
`CREATEROLE` works provided it can connect to each target database.

:::caution[CONNECT on each target database]
Databases grant `CONNECT` to `PUBLIC` by default, so this is usually already
true. If your deployment revokes that, grant it explicitly:

```sql
GRANT CONNECT ON DATABASE appdb TO waypoint_admin;
```

Without it, provisioning for that database fails with
`permission denied for database "appdb"` (SQLSTATE 42501).
:::

## `[provisioning]`

```toml
[provisioning]
allow_raw_sql = false
```

When `false`, ACL grants that include a `sql` field (raw SQL templates run during role provisioning) are rejected at evaluation time. This forces ACL authors to stick to the named presets (`readonly`, `readwrite`, `admin`) and the structured `schemas` / `databases` fields.

Per-listener overrides are also supported, so you can disable raw SQL globally and re-enable it on a single listener that needs it:

```toml
[provisioning]
allow_raw_sql = false

[listeners.postgres]
allow_raw_sql = true   # per-listener override
```

Recommended posture: leave `allow_raw_sql = false` and only enable it on listeners where you need it. See [Raw SQL](/waypoint/acl/raw-sql/) for the grant-side details.

## `[defaults.limits]`

Per-user limit ceilings that apply when an ACL grant doesn't specify its own:

```toml
[defaults.limits]
max_conns_total = 200
# max_conns_per_user = 10
# max_conn_duration = "1h"
# max_bytes_per_conn = "10GB"
```

A grant's `limits` block overrides these per-call; missing fields fall back to the defaults. Setting a default of `0` for a counter-style limit means "unlimited" — be explicit if that's the intent.
