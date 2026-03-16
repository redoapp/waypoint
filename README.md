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

[[listeners]]
name = "raw-mysql"
listen = ":3306"
mode = "tcp"
backend = "10.0.1.5:3306"
```

### Tailscale ACL grants

Access is controlled by Tailscale ACL capability grants. Example policy snippet:

```json
{
  "grants": [{
    "src": ["group:backend"],
    "dst": ["tag:waypoint"],
    "cap": {
      "redo.com/cap/waypoint": [{
        "backends": ["pg-main"],
        "pg": {
          "databases": {
            "myapp": { "permissions": ["SELECT", "INSERT", "UPDATE"] },
            "*":     { "permissions": ["SELECT"] }
          }
        },
        "limits": {
          "max_conns": 10,
          "max_conn_duration": "1h"
        }
      }]
    }
  }]
}
```

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
