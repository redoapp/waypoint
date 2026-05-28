---
title: Provisioning & Defaults
description: allow_raw_sql gating and default per-user limits.
sidebar:
  order: 6
---

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
