---
title: Installation
description: Install the Waypoint server binary and prerequisites.
sidebar:
  order: 1
---

Waypoint ships as a single Go binary. It needs:

- A reachable Redis (or Valkey) instance for connection tracking and distributed locks.
- A Tailscale account, an ACL tag for the Waypoint node, and an auth key (or OAuth/WIF credentials).
- For Postgres or MongoDB mode: admin credentials on the backend so Waypoint can create scoped users.

## Build from source

```sh
git clone https://github.com/redoapp/waypoint.git
cd waypoint
go build ./cmd/waypoint/
```

This produces a `waypoint` binary in the current directory. Go 1.26 or newer is required.

The companion `waypoint-monitor` TUI dashboard is a separate binary:

```sh
go build ./cmd/waypoint-monitor/
```

## Container image

Dockerfiles are included at the repo root:

```sh
docker build -t waypoint -f Dockerfile.waypoint .
docker build -t waypoint-monitor -f Dockerfile.waypoint-monitor .
```

## Development environment

The repo uses [devenv](https://devenv.sh) with Nix. After installing devenv and direnv:

```sh
direnv allow   # or: devenv shell --impure
```

This drops you into a shell with Go, golangci-lint, delve, and a local Redis service. Useful scripts:

| Script | What it does |
|---|---|
| `run-proxy` | Runs Waypoint with `waypoint-dev.toml` (sources `.env` if present) |
| `debug-proxy` | Same, under `dlv` |
| `test` | `go test ./...` |
| `coverage` | Full coverage report (unit + integration + e2e) |

The `.envrc` must use `--impure` because the devenv shell depends on environment variables (e.g. `TS_AUTHKEY`).
