# Waypoint Production Error Fixes — TODO

Derived from a Datadog investigation (EKS `redoapp-prod`, v0.6.7) that surfaced ~2.8M ERROR spans/logs,
mostly benign handshake noise masking a few real failures. Full plan + trade-offs/risks/expandability:
`~/.claude/plans/use-datadog-to-pull-eager-hartmanis.md`.

Sequencing by impact-vs-effort: **WS1 → WS4 → WS3 → WS2**.

---

## WS1 — Handshake error classification (kills ~2.8M false-error spans) ✅ CODE DONE
Benign client disconnects (MongoDB driver monitoring probes, EOF before auth) were recorded as ERROR
spans. Added benign-disconnect classification + protocol negotiation handling. Build/vet/lint/unit green.

- [x] Add `internal/proxy/span.go`: `isBenignDisconnect(err)` (io.EOF / io.ErrUnexpectedEOF /
      net.ErrClosed / ECONNRESET) + `recordSetupFailure(...)` helper
- [x] Add `waypoint.handshake.aborted` counter in `internal/metrics/metrics.go` + example toml
- [x] Route client-side read sites through helper: `mongodb.go` ReadClientHello + CompleteHandshake
      (post-hello + saslContinue EOF). Backend reads left as errors.
- [x] `client proof mismatch`: `mongowire.ErrAuthFailed` sentinel; proxy logs Warn + increments
      AuthFailures/ConnRejected, span marked non-error (`setup_outcome=auth_failed`)
- [x] PG negotiation codes in `pgwire/startup.go`: `gssEncRequestCode=80877104` (decline `'N'`) and
      `cancelRequestCode=80877102` (sentinel `ErrCancelRequest`, close cleanly)
- [x] Route `postgres.go` read-startup failures through benign classifier; handle ErrCancelRequest
- [x] Tests: pgwire GSS/Cancel/EOF cases + `isBenignDisconnect` unit test
- [ ] Mongo integration span-status assertions (needs Docker/testcontainers — not yet added)
- [ ] Audit Datadog monitors keyed on `waypoint.connection.setup` error rate before shipping (ops)
- [ ] Run full integration + e2e suites locally before merge

## WS4 — Observability hygiene
- [ ] `env:none`: build OTEL `resource.Resource` from DD_ENV/DD_SERVICE/DD_VERSION; attach via
      `sdktrace.WithResource` (`tracing.go:21`) + `sdkmetric.WithResource` (`metrics.go:150`)
- [ ] Resolve service-name split (`waypoint` traces vs `waypoint-proxy` logs) — pick canonical name
- [ ] tsnet logs at `status:error`: set `srv.UserLogf`→Info / `srv.Logf`→Debug in `tsconfig.go:79` Apply
      + proxy `server.go:142-143`
- [ ] Tests: assert provider resource has deployment.environment/service.name; verify tsnet lines emit as JSON

## WS3 — Provision lock contention (~1.5k lock timeouts + connection teardowns)
- [ ] In-process `singleflight` per-role in `Provisioner`/`MongoProvisioner` to coalesce local concurrent conns
- [ ] Make revalidation lock failure non-fatal (`postgres.go:477-494`, `mongodb.go:790-805`) — log+metric+continue
      (DECISION NEEDED: revocation-latency requirement — non-fatal for grant drift, hard-fail if user de-authorized)
- [ ] Configurable lock policy: `LockConfig` under `ProvisioningConfig` (`config.go:28-30`); shared
      `acquireRoleLock` helper replacing 3 duplicated const blocks; add jitter
- [ ] Optional reval fast-path: skip lock if memberships already match (reuse IsGroupReady/MarkGroupReady)
- [ ] Keep Redis lock for cross-proxy write safety; keep token-checked ReleaseLock
- [ ] Tests: strengthen ConcurrentPasswordRotation to "all succeed"; reval-lock-timeout-not-fatal test;
      ErrLockTimeout/errors.Is unit test

## WS2 — Backend dial & cert-fetch timeouts
- [ ] IP failover in `tsdns.go:212-242` (`newDialerWithLookup`) — iterate all resolved IPs, per-IP deadline,
      transient classification, shuffle
- [ ] Shared `proxy.dialBackend` helper extracted from `tcp.go:113-131`/`postgres.go:262-282`/`mongodb.go:201-220`
      — bounded retries + jittered backoff on transient errors
- [ ] Cert cache + background pre-warm/renew wrapping `lc.GetCertificate` (`server.go:531-540`) with non-zero
      min_validity (~48h); serve stale-but-valid on fetch error
- [ ] Bound handshake with `conn.SetDeadline` (~15s) in `pgwire/startup.go:43-46` + mongo TLS accept — CLEAR
      before relay
- [ ] Config: per-listener `BackendDialConfig` + cert block; defaults preserve current behavior
- [ ] Tests: tsdns multi-IP failover; proxy transient-then-success dial; server cert cache/refresh; slow-cert handshake

---

## Forward-looking (not in current scope; flagged during WS1)
- [ ] Postgres protocol 3.2 (`196610`): code hard-checks `Expected 196608` (3.0) via pgx
      `pgproto3.StartupMessage.Decode`. PG 18 added protocol 3.2 + `NegotiateProtocolVersion`. No 3.2
      clients in prod today (30d Datadog: only CancelRequest), but future libpq/driver upgrades will hit
      the same "Bad startup message version number" rejection. Separate ticket: protocol-version negotiation.

## Cross-cutting (do as part of WS2/WS3 since all 3 proxies get edited anyway)
- [ ] Extract shared `dialBackend` + lock helpers as protocol-agnostic shared code (pays forward to new DBs)
- [ ] Optional minimal `Provisioner` interface (`EnsureUser`/`ReconcileRole`) — low-risk
- [ ] NOT now: full `Proxy` interface / shared wire framework (separate extensibility effort)

## Verification (every workstream, per CLAUDE.md)
- [ ] `go build -tags integration ./...` (integration files invisible to plain `go test`)
- [ ] `golangci-lint run`
- [ ] `go test ./...` + integration + e2e
- [ ] Post-deploy: re-run Datadog queries, confirm error spans drop, env tag present, monitor logs not error
