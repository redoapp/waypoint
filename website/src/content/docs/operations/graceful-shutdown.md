---
title: Graceful Shutdown
description: SIGINT and SIGTERM drain active connections before exit.
sidebar:
  order: 3
---

On `SIGINT` or `SIGTERM`, Waypoint:

1. Stops accepting new connections on every listener.
2. Unregisters its heartbeat from Redis so `waypoint-monitor` and other observers stop seeing it immediately.
3. Releases its slot in any Tailscale Service it was advertising.
4. Waits for in-flight connections to close on their own.

The process does not force-close active connections — clients see normal end-of-session behavior whenever they finish.

## Timeout

By default Waypoint waits indefinitely for connections to drain. For Kubernetes-style deployments, configure your orchestrator to send `SIGTERM` first and `SIGKILL` after your drain window:

```yaml
# Kubernetes pod spec
terminationGracePeriodSeconds: 300
```

A 5-minute grace period covers most short interactive sessions. For deployments with very long-lived connections (multi-hour ETL jobs, persistent app connections), either set a longer grace period or design your clients to reconnect when killed.

## Rolling updates

Because graceful shutdown drains rather than killing connections, rolling updates of a multi-instance deployment cause zero connection failures **for new connections**. Existing connections to the old pod continue until they end naturally (or the grace period expires).

For Tailscale-Service deployments, the service load-balances across all instances advertising it, so once an instance unregisters, no new connections arrive — only drain remains.
