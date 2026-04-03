# Tailscale Services

Waypoint can register listeners as [Tailscale Services](https://tailscale.com/kb/1438/tailscale-services) using the `service` field. This gives each listener its own stable FQDN (e.g. `waypoint-db.tailf3d5b.ts.net`) that is load-balanced across all nodes hosting the service.

## Configuration

Add a `service` field to a listener:

```toml
[tailscale]
hostname = "waypoint-proxy"

[[listeners]]
name = "pg-main"
listen = ":5432"
mode = "postgres"
backend = "10.0.1.10:5432"
service = "svc:waypoint-db"
```

For the monitor's SSH service:

```toml
[tailscale]
hostname = "waypoint-mgr"

[ssh]
enabled = true
service = "svc:waypoint-ssh"
```

## Tailscale Admin Prerequisites

`ListenService()` advertises the node as a host for the service, but the service must be pre-configured in the Tailscale admin console. Without these steps the service will not appear or function correctly.

1. **Create an ACL tag** (e.g. `tag:waypoint`) and assign it as an owner.
2. **Define the service** in the Tailscale admin panel under Services (e.g. `svc:waypoint-db` on TCP port 5432).
3. **Configure auto-approval** so the service automatically accepts devices with the host tag.
4. **Define access grants** allowing clients to reach the service.
5. **Generate an auth key** tagged with the host tag and set it as `TS_AUTHKEY` or in the config.

If any of these steps are missing, `ListenService()` may succeed at the API level but the service will not be reachable or visible in the admin panel.

## DNS Shadowing Pitfall

The Tailscale hostname and the service name (without `svc:` prefix) **must not match**. When they collide — e.g. `hostname = "waypoint-db"` and `service = "svc:waypoint-db"` — both resolve to the same FQDN. The machine's DNS entry shadows the service, making the service invisible in the Tailscale admin panel.

Waypoint validates this at config load time and rejects the configuration with an error. To fix it, use a different hostname:

```toml
# Bad — hostname shadows the service
[tailscale]
hostname = "waypoint-db"    # resolves to waypoint-db.<tailnet>.ts.net

[[listeners]]
service = "svc:waypoint-db" # also resolves to waypoint-db.<tailnet>.ts.net — shadowed!

# Good — distinct hostname
[tailscale]
hostname = "waypoint-proxy"

[[listeners]]
service = "svc:waypoint-db"
```

## Constraints

- Service hosts **must be tagged nodes**. Untagged nodes receive `ErrUntaggedServiceHost`.
- A host must advertise **all ports** defined for the service. If the service is defined with ports 5432 and 3306, you need two `ListenService` calls (two listeners with the same `service` value).
- Requires **Tailscale v1.86.0 or later**.
