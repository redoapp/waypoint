# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Waypoint

Waypoint is a Tailscale-aware database proxy that authenticates connections using Tailscale identity and ACL capability grants (`redo.com/cap/waypoint`). It supports two modes: **Postgres mode** (intercepts PG wire protocol, dynamically provisions per-user roles) and **TCP mode** (transparent L4 proxy for any TCP backend).

## Development Environment

Requires [devenv](https://devenv.sh) with Nix. The `.envrc` must use `--impure`.

```sh
direnv allow   # or: devenv shell --impure
```

This provides Go 1.26, golangci-lint, delve, and a local Redis service.

## Build

```sh
go build ./cmd/waypoint/
go build ./cmd/waypoint-monitor/
```

## Test

```sh
# Unit tests
go test ./...

# Single test
go test ./internal/auth/ -run TestAuthorize

# Integration tests (require Docker/Podman, use testcontainers)
go test -tags integration -run 'TestIntegration' -race ./...

# E2E tests (use mock Tailscale control plane)
go test -tags integration -run 'TestE2E' -race -timeout 120s ./test/e2e

# Coverage (devenv scripts)
coverage          # full (unit + integration + e2e)
coverage-unit     # unit only
coverage-serve    # serve HTML report on :8080
```

Integration and E2E tests are gated behind the `integration` build tag. Ryuk (testcontainers reaper) is disabled via env var for rootless Podman compatibility.

**Important:** When changing function signatures or interfaces in any package, always build and verify with `-tags integration` to catch integration test breakage. These files are invisible to `go test ./...` without the tag. Run at minimum:

```sh
go build -tags integration ./...
```

## Lint

```sh
golangci-lint run
```

Enabled linters: `govet`, `staticcheck`. Pre-commit hooks run `gofmt` and `golangci-lint`.

## Run Locally

```sh
run-proxy      # runs with waypoint-dev.toml (sources .env if present)
debug-proxy    # same but under delve debugger
```

Requires `TS_AUTHKEY` environment variable for initial Tailscale authentication.

## Architecture

### Request Flow

1. Client connects to a listener on the tailnet
2. `auth` package calls Tailscale `WhoIs` to identify the caller, then checks `CapMap` for `redo.com/cap/waypoint` capability grants
3. `restrict` package checks per-user connection limits (concurrent connections, bandwidth, duration) stored in Redis
4. In Postgres mode: `provision` package creates a temporary PG role with scoped permissions using admin credentials, `pgwire` handles the wire protocol handshake
5. Traffic is proxied to the backend with byte counting and optional mid-session revalidation
6. On disconnect, connection slot is released in Redis

### Key Packages

- **`cmd/waypoint`** — CLI entrypoint for the main server
- **`internal/server`** — main server; listener accept loop, graceful shutdown, heartbeat publishing
- **`cmd/waypoint-monitor`** — TUI dashboard that discovers instances via Redis
- **`internal/auth`** — Tailscale identity verification and ACL capability parsing
- **`internal/proxy`** — Postgres and TCP proxy implementations (`postgres.go`, `tcp.go`)
- **`internal/provision`** — dynamic PostgreSQL role lifecycle (create, grant, cleanup); uses Redis distributed locks
- **`internal/restrict`** — connection tracking, limits enforcement, Redis-backed state
- **`internal/pgwire`** — PostgreSQL wire protocol (startup messages, SSL negotiation, SCRAM auth)
- **`internal/config`** — TOML config loader with `${VAR}` environment variable expansion
- **`internal/metrics`** — OpenTelemetry metrics and distributed tracing (`tracing.go` handles trace provider setup)
- **`internal/heartbeat`** — publishes instance stats to Redis with TTL for discovery
- **`internal/tsdns`** — DNS resolution via Tailscale local API (workaround for split DNS with subnet routers)

### Testing Patterns

- Unit tests: standard `*_test.go` files
- Integration tests: `//go:build integration` tag, `TestIntegration` prefix, use testcontainers for Postgres/Redis
- E2E tests: `TestE2E` prefix in `test/e2e/waypoint_test.go`, mock Tailscale control plane with DERP server
- Test utilities: `internal/testutil/` (container helpers, Redis test client)
- Coverage exclusions in `.coverignore`: `cmd/`, `internal/admin/`, `internal/testutil/`

### Configuration

TOML config file (default `waypoint.toml`). Key sections: `[tailscale]`, `[redis]`, `[revalidation]`, `[metrics]`, `[[listeners]]`. See `examples/waypoint.toml` for reference.

### Key Dependencies

- `tailscale.com` — tsnet integration
- `github.com/jackc/pgx/v5` — PostgreSQL driver
- `github.com/redis/go-redis/v9` — Redis client
- `github.com/pires/go-proxyproto` — PROXY protocol support
- `github.com/testcontainers/testcontainers-go` — Docker-based test infrastructure
