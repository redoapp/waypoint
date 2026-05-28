---
title: TCP
description: Transparent L4 proxy for any TCP backend.
sidebar:
  order: 3
---

TCP mode is a transparent byte-pipe: clients connect, Waypoint authenticates them via Tailscale identity + ACL grants, then proxies bytes to and from the backend. It does not parse or modify the wire protocol.

Use it for any TCP service where you want identity-based access control but don't need per-user backend credential provisioning — MySQL, Redis, internal HTTP services, anything else.

```toml
[[listeners]]
name = "raw-mysql"
listen = ":3306"
mode = "tcp"
backend = "10.0.1.5:3306"
```

## Backend over Tailscale

When the backend is itself a tailnet host (a MagicDNS name or `100.x.y.z`), set `backend_via_tailscale = true`. Waypoint resolves and dials through tsnet rather than the host's default routing:

```toml
[[listeners]]
name = "ts-backend"
listen = ":6379"
mode = "tcp"
backend = "my-redis.tail-scale.ts.net:6379"
backend_via_tailscale = true
```

## What TCP mode does NOT do

- **No per-user backend credentials.** The backend sees a single connection from Waypoint; clients still need to authenticate to the backend themselves with whatever mechanism it offers.
- **No protocol parsing.** Connection limits, byte counting, and revalidation still work (they operate on the TCP stream), but Waypoint can't enforce per-table or per-database permissions for backends it doesn't speak.
- **No TLS termination semantics specific to the backend protocol.** If the backend uses STARTTLS-style negotiation, the bytes pass through unmodified.

## ACL grants for TCP listeners

ACL grants reference TCP listeners by their `name`:

```json
{
  "cap": {
    "redo.com/cap/waypoint": [{
      "backends": {
        "raw-mysql": {}
      }
    }]
  }
}
```

An empty backend object means "allowed, with no per-protocol constraints". You can still set `limits` at the top level to cap concurrent connections, bytes, or duration.
