---
title: Raw SQL Grants
description: Go-templated SQL for cases the presets don't cover.
sidebar:
  order: 3
---

For advanced cases the presets don't cover — specific tables, `REVOKE`, `ALTER DEFAULT PRIVILEGES`, materialized views, foreign servers — a database grant can include a `sql` field with Go templates that are run during role provisioning.

```json
{
  "databases": {
    "myapp": {
      "permissions": ["readonly"],
      "sql": [
        "GRANT INSERT ON public.audit_log TO {{.Role}}",
        "GRANT USAGE ON SCHEMA analytics TO {{.Role}}",
        "GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO {{.Role}}"
      ]
    }
  }
}
```

## Template variables

| Variable | Value |
|---|---|
| `{{.Role}}` | The dynamically created backend role name (e.g. `wp_alice_laptop_myapp`). Always quote-safe. |
| `{{.Database}}` | The target database name. |
| `{{.User}}` | The caller's Tailscale login (loginName). |

## Server-side gating

Raw SQL is **disabled by default** server-side via the `[provisioning]` section:

```toml
[provisioning]
allow_raw_sql = false   # rejects ACL grants that include `sql`
```

When `false`, any grant carrying a `sql` field is treated as an authorization failure for that connection. Per-listener overrides let you enable raw SQL only on listeners that need it:

```toml
[listeners.postgres]
allow_raw_sql = true
```

See [Provisioning & Defaults](/waypoint/configuration/provisioning/).

## Recommendations

- Keep raw SQL grants short and idempotent — they run on every connect.
- Use them to **add** permissions on top of a preset, not to define the whole grant from scratch.
- Audit any grant containing `sql` carefully — it has full backend-side capability subject only to the `admin_user`'s privileges.
- If you find yourself templating the same SQL in many grants, prefer a stored procedure on the backend.
