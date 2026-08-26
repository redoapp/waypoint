---
title: Role Cleanup
description: How provisioned PostgreSQL and CockroachDB roles are aged out.
sidebar:
  order: 2
---

## Role naming

A provisioned role is named:

```
<user_prefix><listener>_<login>_<node>_<database>[_<scope>]
```

for example `wp_pg_main_alice_example_com_laptop_appdb`.

Postgres identifiers are limited to 63 bytes and MongoDB user names to 128. A
name over the limit keeps its first 52 characters (117 for MongoDB), then an
underscore, then a 10-character hash suffix — filling the limit exactly:

```
wp_pg_main_very_long_email_address_for_testing_extre_60c64df4fb
└───────────────── 52 kept ────────────────────────┘ └─ hash ─┘
```

The suffix is a digest of the characters that were dropped, not of the whole
name. That is sufficient for uniqueness — two names surviving to the same kept
prefix can differ only in what was dropped — and it means the suffix
identifies precisely what is missing.

### Tracing a truncated name back

A truncated name is logged once per distinct name, at `INFO`, so an identifier
seen later in `pg_stat_activity` or an audit log can be cross-referenced:

```json
{
  "msg": "role name truncated to fit",
  "name": "wp_pg_main_very_long_email_address_for_testing_extre_60c64df4fb",
  "original": "wp_pg_main_very_long_email_address_for_testing_extremely_long_domain_example_com_super_extremely_long_node_hostname_very_long_database_name",
  "original_bytes": 139,
  "limit": 63,
  "dropped": "mely_long_domain_example_com_super_extremely_long_node_hostname_very_long_database_name"
}
```

`dropped` is exactly the text the hash covers, so the record alone is enough to
reproduce the name. Search your logs for the `name` field to find the identity
behind an unfamiliar role.

The record is emitted once per distinct original name per process — a role name
is derived on every connection, and logging each one would bury the fact for
any user whose name always truncates. It is keyed on the original rather than
the result, so two different names collapsing onto one identifier would produce
two records rather than silently hiding the collision.

The **listener** is part of the name because two listeners over the same
backend can carry different capability grants. Were they to share a role,
whichever provisioned most recently would set that role's privileges for both.
Including the listener means a web console and a wire-protocol listener can
sit on one backend with different access and no interference — and it makes a
role in `pg_stat_activity` attributable to the listener that created it. The
listener leads the name rather than trailing it so that it survives truncation.

MongoDB users are named the same way, minus the database component.

:::caution[Renaming orphans existing roles]
Waypoint 0.x releases before this change named roles without the listener
component. Upgrading does not rename existing roles — new connections simply
provision new ones, and the old roles remain until dropped. Since the cleanup
loop below is not yet implemented, they will not age out on their own. To find
and remove them:

```sql
-- roles under the prefix that do not name a current listener
SELECT rolname FROM pg_roles WHERE rolname LIKE 'wp\_%';
```

Drop the stale ones with `REASSIGN OWNED BY <role> TO CURRENT_USER;
DROP OWNED BY <role>; DROP ROLE <role>;` once no session is using them.
:::

## PostgreSQL

:::danger[Not implemented]
The cleanup loop described below does not exist in the code. `user_ttl` is
accepted in configuration and currently ignored: no role is aged out
automatically on any backend. Treat this section as the intended design, and
prune manually until it is built.
:::

The intended behaviour is a periodic cleanup loop that:

1. Lists roles with the configured `user_prefix` (default `wp_`).
2. Checks each role's last-use timestamp tracked in Redis.
3. For roles past `user_ttl` with no recent activity, runs:

   ```sql
   REASSIGN OWNED BY <role> TO CURRENT_USER;
   DROP OWNED BY <role>;
   DROP ROLE IF EXISTS <role>;
   ```

This keeps the role count bounded over time. Cleanup is idempotent and safe to run while other connections are active — Postgres rejects the drop if anyone is connected as that role.

## CockroachDB

Waypoint **does not** automatically clean up roles on CockroachDB. See [CockroachDB](/waypoint/listeners/cockroachdb/) for why this is safe in practice and how to clean up manually if role accumulation becomes a concern.

## MongoDB

For `provision.mode = "database"`, Waypoint creates and updates users as needed but does not currently age them out automatically. They're harmless when idle (no traffic, no auth attempts) but if you want to prune them, drop `wp_*` users via the standard `dropUser` command.

For `provision.mode = "static"`, there's nothing to clean up — Waypoint never creates users, it only selects pre-existing ones.

## Forcing a cleanup pass

Restart the Waypoint process. The cleanup loop runs at startup and then on its internal cadence; restart kicks the first pass immediately.

## Observability

Watch the cleanup counters in [Metrics](/waypoint/observability/metrics/):

- `waypoint.cleanup.runs` — number of cleanup passes completed.
- `waypoint.cleanup.dropped` — number of roles successfully dropped.
