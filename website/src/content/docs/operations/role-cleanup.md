---
title: Role Cleanup
description: How provisioned PostgreSQL and CockroachDB roles are aged out.
sidebar:
  order: 2
---

## PostgreSQL

For PostgreSQL backends, Waypoint runs a periodic cleanup loop that:

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
