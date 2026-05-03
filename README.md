# Waypoint

Waypoint is a Tailscale-aware database proxy that authenticates connections using Tailscale identity and ACL capability grants. It sits between clients on a tailnet and backend databases, enforcing per-user permissions, connection limits, and bandwidth budgets — with no passwords on the client side.

## Features

- **Tailscale-native auth** — identifies callers via `tsnet` + `WhoIs`, checks `redo.com/cap/waypoint` capability grants from your ACL policy
- **Postgres mode** — intercepts the PG wire protocol, dynamically provisions per-user database roles with scoped `GRANT` permissions, and cleans up expired users
- **TCP mode** — transparent L4 proxy for any TCP backend (MySQL, Redis, etc.)
- **Connection tracking** — per-user limits on concurrent connections, bytes transferred, connection duration, and bandwidth budgets, all stored in Redis/Valkey
- **Mid-session revalidation** — periodically re-checks Tailscale identity during long-lived connections
- **Graceful shutdown** — drains active connections on `SIGINT`/`SIGTERM`

## Configuration

Waypoint reads a TOML config file (default: `waypoint.toml`). Environment variables can be interpolated with `${VAR}` syntax. See [`examples/waypoint.toml`](examples/waypoint.toml) for a full example.

```toml
[tailscale]
hostname = "waypoint-db"
state_dir = "/var/lib/waypoint/tsnet"

[redis]
address = "localhost:6379"
key_prefix = "waypoint:"

[revalidation]
interval = "1m"

# Optional: restrict ACL grants to presets only (no raw SQL)
[provisioning]
allow_raw_sql = false

[[listeners]]
name = "pg-main"
listen = ":5432"
mode = "postgres"
backend = "10.0.1.10:5432"

[listeners.postgres]
admin_user = "waypoint_admin"
admin_password = "${PG_ADMIN_PASSWORD}"
admin_database = "postgres"
user_prefix = "wp_"
user_ttl = "24h"
# allow_raw_sql = true  # per-listener override

[[listeners]]
name = "raw-mysql"
listen = ":3306"
mode = "tcp"
backend = "10.0.1.5:3306"
```

### Tailscale ACL grants

Access is controlled by Tailscale ACL capability grants. The `permissions` field accepts named presets:

| Preset | Grants |
|--------|--------|
| `readonly` | `USAGE` on schema, `SELECT` on all tables and sequences |
| `readwrite` | Everything in `readonly` + `INSERT`, `UPDATE`, `DELETE` on tables, `USAGE` on sequences |
| `admin` | `ALL PRIVILEGES` on tables and sequences, `USAGE` + `CREATE` on schema |

By default, presets apply to the `public` schema. Use `schemas` to target other schemas.

Example policy snippet:

```json
{
  "grants": [{
    "src": ["group:backend"],
    "dst": ["tag:waypoint"],
    "cap": {
      "redo.com/cap/waypoint": [{
        "limits": {
          "max_conns": 10,
          "max_conn_duration": "1h"
        },
        "backends": {
          "pg-main": {
            "pg": {
              "databases": {
                "myapp": {
                  "permissions": ["readwrite"],
                  "schemas": ["public", "app"]
                },
                "*": { "permissions": ["readonly"] }
              }
            }
          }
        }
      }]
    }
  }]
}
```

For advanced use cases (specific tables, `REVOKE`, `ALTER DEFAULT PRIVILEGES`), use the `sql` field with Go templates:

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

The `sql` field can be disabled server-side with `allow_raw_sql = false` in the `[provisioning]` config section.

## Observability

Waypoint exports OpenTelemetry metrics and traces to any OTLP-compatible collector.

```toml
[metrics]
endpoint = "http://otel-collector:4318"
protocol = "http"                        # "http" (default) or "grpc"
interval = "30s"
tracing_sample_rate = 1.0                # 0 = disabled, 1.0 = trace all requests

[metrics.enable]
"waypoint.conn.active"   = ["listener", "mode"]
"waypoint.conn.total"    = ["listener", "mode"]
"waypoint.auth.attempts" = ["listener"]
```

**Metrics** are opt-in per metric name via `[metrics.enable]`. The value array controls which attribute tags are allowed (use `["*"]` for all).

**Tracing** is enabled when `tracing_sample_rate > 0` and an endpoint is configured. Traces cover:
- Connection setup (auth, slot acquisition, backend dial, PG provisioning)
- Redis operations (lock, counters, bandwidth)
- Mid-session revalidation checks
- Connection close (final byte counts, duration)

Long-lived connections use linked spans rather than holding a single span open — the setup span ends once the relay begins, and revalidation/close events link back for correlation.

## Usage

```
waypoint [-config path/to/waypoint.toml]
```

Set `TS_AUTHKEY` to authenticate the tsnet node on first run.

## Development

Requires [devenv](https://devenv.sh):

```sh
direnv allow   # or: devenv shell --impure
go build ./cmd/waypoint/
test           # runs go test ./...
coverage       # runs tests with coverage report
```

Integration tests use [testcontainers](https://golang.testcontainers.org/) and require Docker.

## License

MIT — see [LICENSE](LICENSE).
