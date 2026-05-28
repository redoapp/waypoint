---
title: TLS
description: tls_mode, Tailscale-managed certificates, and custom certs.
sidebar:
  order: 4
---

Each listener can terminate TLS for its clients. Configuration is consistent across Postgres and MongoDB modes.

```toml
[[listeners]]
name = "pg-main"
mode = "postgres"
tls_mode = "optional"               # off | optional | require
use_tailscale_tls = true
# cert_file = "/etc/waypoint/server.crt"
# key_file = "/etc/waypoint/server.key"
```

## tls_mode

| Value | Behavior |
|---|---|
| `off` | Reject TLS upgrade requests; serve plaintext only. |
| `optional` | Upgrade to TLS when the client requests it; otherwise plaintext. **Default.** |
| `require` | Reject plaintext connections. Postgres clients must send `SSLRequest`; MongoDB clients must connect over TLS. |

For Postgres, `optional` matches the historical default: if the client opens with `SSLRequest`, Waypoint upgrades; otherwise it proceeds in cleartext.

## Certificate sources

Waypoint picks a certificate by server name, in this order:

1. **`cert_file` / `key_file`** — admin-provided cert, used when the SNI matches (or when no SNI is sent and a file cert is configured). Use this for custom domains like `waypoint.redo.run`.
2. **Tailscale-managed cert** — fetched via the Tailscale local API for `*.ts.net` names, when `use_tailscale_tls = true` and HTTPS certificates are enabled in the tailnet.

Setting `use_tailscale_tls = false` disables the second source — useful when you want to be sure clients only ever see your file-based cert.

## Backend TLS (MongoDB)

For MongoDB listeners, `tls = true` enables TLS **from Waypoint to each backend member**. This is independent of `tls_mode` (which governs the client side):

```toml
[[listeners]]
mode = "mongodb"
tls = true            # Waypoint → MongoDB
tls_mode = "require"  # client → Waypoint
```

When clients connect over TLS with SNI, Waypoint rewrites the hostnames in MongoDB topology responses (`isMaster`, `hello`) to the SNI hostname, while preserving the advertised listener/member ports. This keeps drivers pinned to the proxy and prevents direct connections to backend members.
