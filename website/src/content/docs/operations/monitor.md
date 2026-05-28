---
title: waypoint-monitor TUI
description: Discover instances and watch live traffic from a terminal.
sidebar:
  order: 1
---

`waypoint-monitor` is a separate binary that gives operators a live, terminal-UI view of every running Waypoint instance.

```sh
go build ./cmd/waypoint-monitor/
waypoint-monitor -config waypoint-monitor.toml
```

## How discovery works

Each Waypoint instance publishes a heartbeat record to Redis with a TTL. The monitor reads the same Redis (using the same `key_prefix`) and renders one row per live instance.

Add the matching Redis section to `waypoint-monitor.toml`:

```toml
[redis]
address = "localhost:6379"
key_prefix = "waypoint:"

[tailscale]
hostname = "waypoint-mgr"
state_dir = "/var/lib/waypoint-monitor/tsnet"
```

The monitor also runs on the tailnet so it can poll instances directly for per-connection detail.

## SSH access to the monitor

The monitor can expose itself over Tailscale SSH, including as a [Tailscale Service](/waypoint/tailscale-services/):

```toml
[ssh]
enabled = true
service = "svc:waypoint-ssh"
```

This lets multiple operators connect to the same monitor view without each running their own copy.

## What you can see

- Instance hostname, uptime, version.
- Active connections per listener.
- Per-user bandwidth and connection counts.
- Recent auth failures and limit violations.

The monitor is read-only — it does not change ACLs, kill connections, or restart instances.
