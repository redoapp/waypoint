---
title: Tailscale
description: tsnet hostname, auth keys, OAuth, and Workload Identity Federation.
sidebar:
  order: 2
---

The `[tailscale]` section controls how Waypoint joins the tailnet as a tsnet node.

```toml
[tailscale]
hostname = "waypoint-db"
state_dir = "/var/lib/waypoint/tsnet"
# auth_key = "${TS_AUTHKEY}"
# control_url = "https://controlplane.tailscale.com"
# ephemeral = false
# advertise_tags = ["tag:waypoint"]
```

## hostname

The MagicDNS name Waypoint registers as. Clients reach Waypoint at `<hostname>.<tailnet>.ts.net`.

:::caution
If you also use Tailscale Services, the hostname **must not** collide with the service name (without the `svc:` prefix). See [Tailscale Services](/waypoint/tailscale-services/) for details — Waypoint rejects colliding configs at load time.
:::

## state_dir

Where tsnet persists its node state (keys, peer cache). Treat it as durable storage; losing it forces re-authentication.

## Authentication

Pick one of three methods:

### Auth key

```toml
auth_key = "${TS_AUTHKEY}"
```

Or set `TS_AUTHKEY` in the environment. The key should be tagged with the same tag the node will advertise (e.g. `tag:waypoint`).

### OAuth client credentials

```toml
client_secret = "${TS_CLIENT_SECRET}"
advertise_tags = ["tag:waypoint"]
```

Requires `advertise_tags`. The OAuth client's owner must be allowed to assert those tags.

### Workload Identity Federation

For workloads with federated identity (GCP, GitHub Actions, etc.):

```toml
client_id = "your-client-id"
id_token = "${WIF_ID_TOKEN}"
audience = "https://login.tailscale.com"
advertise_tags = ["tag:waypoint"]
```

## ephemeral

When `true`, the tsnet node is removed from the tailnet when Waypoint exits. Use for short-lived test instances; leave `false` for long-running deployments so state stays predictable across restarts.
