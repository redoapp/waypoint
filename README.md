# Waypoint

Waypoint is a Tailscale-aware database proxy that authenticates connections using Tailscale identity and ACL capability grants. It sits between clients on a tailnet and backend databases, enforcing per-user permissions, connection limits, and bandwidth budgets — with no passwords on the client side.

## Features

- **Tailscale-native auth** — identifies callers via `tsnet` + `WhoIs`, checks `redo.com/cap/waypoint` capability grants from your ACL policy
- **Postgres mode** — intercepts the PG wire protocol, dynamically provisions per-user database roles with scoped `GRANT` permissions, and cleans up expired users
- **MongoDB mode** — provisions scoped MongoDB users or uses static backend users, and rewrites replica-set topology so clients stay on the proxy, including TLS-terminated clients
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
tls_mode = "optional"                   # off | optional | require
use_tailscale_tls = true                # default: allow *.ts.net cert lookup
cert_file = "/etc/waypoint/server.crt"  # optional: custom-domain cert
key_file = "/etc/waypoint/server.key"

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

Postgres listeners default to `tls_mode = "optional"`. If a client sends a PostgreSQL `SSLRequest`, Waypoint now upgrades that session to TLS and serves the certificate that matches the requested server name:
- admin-provided `cert_file`/`key_file` for custom domains such as `waypoint.redo.run`
- Tailscale-managed certificates for `*.ts.net` names when HTTPS certificates are enabled in the tailnet

Set `use_tailscale_tls = false` to disable Tailscale certificate lookup and use only the configured file-based certificate.

Use `tls_mode = "require"` to reject plaintext Postgres clients.

MongoDB replica sets can be exposed as one logical listener with one Waypoint
port per member. Set `backend_via_tailscale = true` when Waypoint must reach the
members over Tailscale or subnet routes. For SRV-backed clusters, omit
`[[listeners.mongodb.members]]`; Waypoint resolves the SRV record at startup and
allocates consecutive listener ports starting from `listen`:

```toml
[[listeners]]
name = "mongo-prod"
listen = ":27017"
mode = "mongodb"
backend_via_tailscale = true
tls = true                              # optional: use TLS to MongoDB backends
tls_mode = "require"                    # off | optional | require for clients
use_tailscale_tls = true                # default: allow *.ts.net cert lookup
# cert_file = "/etc/waypoint/mongo.crt" # optional: custom-domain cert
# key_file = "/etc/waypoint/mongo.key"

[listeners.mongodb]
admin_user = "waypoint_admin"
admin_password = "${MONGO_ADMIN_PASSWORD}"
auth_database = "admin"
replica_set = "rs0"
srv = "cluster.example.com"             # resolves _mongodb._tcp.cluster.example.com
srv_max_members = 3                     # binds :27017, :27018, and :27019

[listeners.mongodb.provision]
mode = "database"                       # default: create/update MongoDB users
```

When combining MongoDB SRV discovery with a Tailscale Service, set `advertise`
so topology rewrites can be built before service listeners are registered.

You can also map members explicitly when you need fixed backend/member
addresses:

```toml
[[listeners]]
name = "mongo-prod"
mode = "mongodb"
backend_via_tailscale = true

[listeners.mongodb]
admin_user = "waypoint_admin"
admin_password = "${MONGO_ADMIN_PASSWORD}"
auth_database = "admin"
replica_set = "rs0"

[[listeners.mongodb.members]]
backend = "mongo1.prod.internal:27017"
listen = ":27017"
advertise = "waypoint-db:27017"

[[listeners.mongodb.members]]
backend = "mongo2.prod.internal:27017"
listen = ":27018"
advertise = "waypoint-db:27018"

[[listeners.mongodb.members]]
backend = "mongo3.prod.internal:27017"
listen = ":27019"
advertise = "waypoint-db:27019"
```

For MongoDB listeners, `tls = true` enables TLS from Waypoint to each backend
member. `tls_mode` controls client-facing TLS using the same values as
Postgres: `off`, `optional`, or `require`. When MongoDB clients connect over
TLS with SNI, Waypoint rewrites replica-set topology hosts to that SNI hostname
while preserving the advertised listener/member ports.

MongoDB provisioning supports two modes. `mode = "database"` is the default and
uses `admin_user`/`admin_password` to create or update backend MongoDB users.
For MongoDB Atlas or other environments where user-management commands are not
available, `mode = "static"` selects from pre-created backend users:

```toml
[listeners.mongodb.provision]
mode = "static"

[[listeners.mongodb.provision.static_users]]
name = "app-readwrite"
username = "atlas_app_rw"
password = "${MONGO_APP_RW_PASSWORD}"
auth_database = "admin"
database = "app"
permissions = ["readwrite"]

[[listeners.mongodb.provision.static_users]]
name = "readonly"
username = "atlas_readonly"
password = "${MONGO_READONLY_PASSWORD}"
auth_database = "admin"
permissions = ["readonly"]              # matches any all-readonly grant set
```

Static users must already have the matching roles in MongoDB or Atlas. When
`database` is set, Waypoint matches the exact expanded database role set; when
only `permissions` is set, it matches grants where every database has that same
preset. You only need to configure the static users you want to allow. If an
authorized client requests a grant set with no matching static user, Waypoint
returns a MongoDB authentication error to that client and does not connect to
the backend.

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
