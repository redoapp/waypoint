package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/logging"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/pgwire"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/restrict"
)

// PostgresProxy handles PG-aware proxying with Tailscale auth,
// dynamic user provisioning, and mid-session revalidation.
type PostgresProxy struct {
	Backend       string
	Name          string
	Auth          Authorizer
	Tracker       *restrict.Tracker
	Provisioner   *provision.Provisioner
	Metrics       *metrics.Metrics
	PGConfig      *config.PostgresAdmin
	ClientTLSMode config.PostgresTLSMode
	ClientTLS     *tls.Config
	BackendTLS    bool
	RevalInterval time.Duration
	Logger        *slog.Logger
	Dialer        func(ctx context.Context, network, addr string) (net.Conn, error)
	BytesRead     *atomic.Int64 // optional: aggregate byte counter
	BytesWritten  *atomic.Int64 // optional: aggregate byte counter
}

// HandleConn processes a single inbound PostgreSQL connection.
func (p *PostgresProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
	defer func() {
		if clientConn != nil {
			clientConn.Close()
		}
	}()

	connID := logging.NewConnID()
	log := p.Logger.With("conn_id", connID, "remote", clientConn.RemoteAddr())
	log.DebugContext(ctx, "connection accepted")

	m := p.Metrics
	tracer := m.Tracer()
	listenerAttr := metrics.AttrListener.String(p.Name)
	modeAttr := metrics.AttrMode.String("postgres")

	// Setup span covers auth → provision → dial → PG handshake.
	ctx, setupSpan := tracer.Start(ctx, "waypoint.connection.setup",
		trace.WithAttributes(
			attribute.String("waypoint.conn_id", connID),
			attribute.String("waypoint.listener", p.Name),
			attribute.String("waypoint.mode", "postgres"),
			attribute.String("waypoint.backend", p.Backend),
		),
	)
	setupSpanCtx := setupSpan.SpanContext()

	// Step 1: Authorize via Tailscale identity.
	m.AuthAttempts.Add(ctx, 1, m.Attrs("waypoint.auth.attempts", listenerAttr))
	ctx, authSpan := tracer.Start(ctx, "waypoint.auth")
	authStart := time.Now()
	result, err := p.Auth.Authorize(ctx, clientConn.RemoteAddr().String(), p.Name)
	authDur := time.Since(authStart).Seconds()
	m.AuthLatency.Record(ctx, authDur, m.Attrs("waypoint.auth.latency", listenerAttr))
	if err != nil {
		authSpan.RecordError(err)
		authSpan.SetStatus(codes.Error, "auth failed")
		authSpan.End()
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "auth failed")
		setupSpan.End()
		m.AuthFailures.Add(ctx, 1, m.Attrs("waypoint.auth.failures", listenerAttr))
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		log.WarnContext(ctx, "auth failed", "error", err, "listener", p.Name)
		pgwire.SendErrorResponse(clientConn, "FATAL", "28000", "authentication failed: "+err.Error())
		return
	}
	authSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	authSpan.End()

	log.InfoContext(ctx, "authorized",
		"user", result.LoginName,
		"node", result.NodeName,
		"backend", p.Name,
	)

	// Step 2: Acquire connection slot.
	ctx, slotSpan := tracer.Start(ctx, "waypoint.acquire_slot")
	release, err := p.Tracker.Acquire(ctx, result.LoginName, result.Limits, p.Name)
	if err != nil {
		slotSpan.RecordError(err)
		slotSpan.SetStatus(codes.Error, "limit exceeded")
		slotSpan.End()
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "limit exceeded")
		setupSpan.End()
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		log.WarnContext(ctx, "limit exceeded", "user", result.LoginName, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "53300", "too many connections: "+err.Error())
		return
	}
	slotSpan.End()
	defer release()
	log.DebugContext(ctx, "connection slot acquired")

	// Track connection.
	connStart := time.Now()
	m.ConnTotal.Add(ctx, 1, m.Attrs("waypoint.conn.total", listenerAttr, modeAttr))
	m.ConnActive.Add(ctx, 1, m.Attrs("waypoint.conn.active", listenerAttr, modeAttr))
	defer func() {
		m.ConnActive.Add(ctx, -1, m.Attrs("waypoint.conn.active", listenerAttr, modeAttr))
		m.ConnDuration.Record(ctx, time.Since(connStart).Seconds(),
			m.Attrs("waypoint.conn.duration", listenerAttr, metrics.AttrUser.String(result.LoginName)))
	}()

	// Step 3: Read client's StartupMessage to get requested database.
	clientConn, startup, err := pgwire.ReadStartupMessage(clientConn, p.ClientTLSMode, p.ClientTLS)
	if err != nil {
		if errors.Is(err, pgwire.ErrTLSRequired) {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "tls required")
			setupSpan.End()
			log.WarnContext(ctx, "client attempted plaintext on TLS-required listener")
			pgwire.SendErrorResponse(clientConn, "FATAL", "28000", "TLS is required for this listener")
			return
		}
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "read startup failed")
		setupSpan.End()
		log.ErrorContext(ctx, "read startup failed", "error", err)
		return
	}

	requestedDB := startup.Parameters["database"]
	if requestedDB == "" {
		requestedDB = startup.Parameters["user"]
	}

	log.DebugContext(ctx, "startup message received", "database", requestedDB)
	setupSpan.SetAttributes(attribute.String("waypoint.database", requestedDB))

	presetLimit, err := postgresPresetLimitFromStartup(startup.Parameters)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "invalid preset limit")
		setupSpan.End()
		log.WarnContext(ctx, "invalid preset limit", "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "22023", err.Error())
		return
	}

	// Step 4: Check per-database permissions from cap rules.
	dbPerms := auth.DatabasePermissions(result, p.Name, requestedDB)
	if dbPerms == nil {
		var grantedDBs []string
		seen := make(map[string]bool)
		for _, r := range result.MatchedRules {
			bc, ok := r.Backends[p.Name]
			if !ok || bc.PG == nil {
				continue
			}
			for db := range bc.PG.Databases {
				if !seen[db] {
					grantedDBs = append(grantedDBs, db)
					seen[db] = true
				}
			}
		}
		setupSpan.SetStatus(codes.Error, "no permissions for database")
		setupSpan.End()
		log.WarnContext(ctx, "no permissions for database",
			"user", result.LoginName,
			"database", requestedDB,
			"granted_databases", grantedDBs,
		)
		pgwire.SendErrorResponse(clientConn, "FATAL", "42501",
			"not authorized for database "+requestedDB)
		return
	}

	roleScope := ""
	if presetLimit != nil {
		var effectivePreset string
		dbPerms, effectivePreset, err = limitDBPermissionsToPostgresPreset(dbPerms, presetLimit)
		if err != nil {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "preset limit denied")
			setupSpan.End()
			log.WarnContext(ctx, "preset limit denied",
				"user", result.LoginName,
				"database", requestedDB,
				"preset_limit", presetLimit.Raw,
				"error", err,
			)
			pgwire.SendErrorResponse(clientConn, "FATAL", "42501",
				"not authorized for requested preset limit: "+err.Error())
			return
		}
		roleScope = "preset_" + effectivePreset
		setupSpan.SetAttributes(
			attribute.String("waypoint.preset_limit", presetLimit.Raw),
			attribute.String("waypoint.effective_preset", effectivePreset),
		)
		log.DebugContext(ctx, "preset limit applied",
			"database", requestedDB,
			"preset_limit", presetLimit.Raw,
			"effective_preset", effectivePreset,
		)
	}

	log.DebugContext(ctx, "database permissions resolved",
		"database", requestedDB,
		"permissions", dbPerms.Permissions,
		"sql_count", len(dbPerms.SQL),
	)

	// Step 5: Provision dynamic PG user.
	provStart := time.Now()
	m.ProvisionTotal.Add(ctx, 1, m.Attrs("waypoint.provision.total", listenerAttr))
	ctx, provSpan := tracer.Start(ctx, "waypoint.provision")
	var pgUser, pgPass string
	if roleScope != "" {
		pgUser, pgPass, err = p.Provisioner.EnsureUserWithRoleScope(ctx, result.LoginName, result.NodeName, requestedDB, roleScope, dbPerms)
	} else {
		pgUser, pgPass, err = p.Provisioner.EnsureUser(ctx, result.LoginName, result.NodeName, requestedDB, dbPerms)
	}
	provSpan.End()
	m.ProvisionLatency.Record(ctx, time.Since(provStart).Seconds(),
		m.Attrs("waypoint.provision.latency", listenerAttr))
	if err != nil {
		m.ProvisionErrors.Add(ctx, 1, m.Attrs("waypoint.provision.errors", listenerAttr))
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "provision failed")
		setupSpan.End()
		log.ErrorContext(ctx, "provision failed",
			"user", result.LoginName,
			"database", requestedDB,
			"error", err,
		)
		pgwire.SendErrorResponse(clientConn, "FATAL", "58000", "internal error")
		return
	}

	log.DebugContext(ctx, "user provisioned", "pg_user", pgUser, "database", requestedDB)

	// Step 6: Connect to upstream PG with provisioned credentials.
	ctx, dialSpan := tracer.Start(ctx, "waypoint.dial_backend")
	var backendConn net.Conn
	if p.Dialer != nil {
		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		defer dialCancel()
		backendConn, err = p.Dialer(dialCtx, "tcp", p.Backend)
	} else {
		backendConn, err = net.DialTimeout("tcp", p.Backend, 10*time.Second)
	}
	if err != nil {
		dialSpan.RecordError(err)
		dialSpan.SetStatus(codes.Error, "dial failed")
		dialSpan.End()
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "dial failed")
		setupSpan.End()
		log.ErrorContext(ctx, "backend dial failed", "backend", p.Backend, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "08006", "backend unavailable")
		return
	}
	dialSpan.End()
	defer backendConn.Close()

	log.DebugContext(ctx, "backend connected")

	// Step 6b: Upgrade to TLS if configured.
	if p.BackendTLS {
		backendConn, err = pgwire.UpgradeToTLS(backendConn)
		if err != nil {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "backend TLS failed")
			setupSpan.End()
			log.ErrorContext(ctx, "backend TLS upgrade failed", "error", err)
			pgwire.SendErrorResponse(clientConn, "FATAL", "08006", "backend TLS failed")
			return
		}
		log.DebugContext(ctx, "backend TLS established")
	}

	// Step 7: Send startup to upstream with provisioned user.
	if err := pgwire.WriteStartupMessage(backendConn, pgUser, requestedDB, nil); err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "send startup failed")
		setupSpan.End()
		log.ErrorContext(ctx, "send startup failed", "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "08006", "backend error")
		return
	}

	// Step 8: Handle upstream auth.
	upstreamFE, err := pgwire.HandleUpstreamAuth(backendConn, pgUser, pgPass)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "upstream auth failed")
		setupSpan.End()
		log.ErrorContext(ctx, "upstream auth failed", "user", pgUser, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "28P01", "backend authentication failed")
		return
	}

	log.DebugContext(ctx, "upstream auth complete")

	// Step 9: Send AuthenticationOk to client (Tailscale identity = their credential).
	if err := pgwire.SendAuthOK(clientConn); err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "send auth ok failed")
		setupSpan.End()
		log.ErrorContext(ctx, "send auth ok failed", "error", err)
		return
	}

	// Step 10: Forward post-auth messages (ParameterStatus, BackendKeyData, ReadyForQuery).
	if err := pgwire.ForwardPostAuth(upstreamFE, clientConn); err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "forward post-auth failed")
		setupSpan.End()
		log.ErrorContext(ctx, "forward post-auth failed", "error", err)
		return
	}

	// Setup complete — end span before long-lived relay.
	setupSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	setupSpan.End()

	// Step 11: Bidirectional relay with limits.
	cl := p.Tracker.WrapConn(ctx, result.LoginName, result.Limits, p.Name)

	// Step 12: Start mid-session revalidation.
	revalCtx, revalCancel := context.WithCancel(ctx)
	defer revalCancel()
	if p.RevalInterval > 0 {
		go p.revalidateLoop(revalCtx, setupSpanCtx, connID, clientConn, backendConn, result.LoginName, requestedDB, pgUser, presetLimit, log)
	}

	log.DebugContext(ctx, "relay started")

	relayResult := restrict.Relay(clientConn, backendConn, cl)

	switch relayResult.Reason {
	case restrict.CloseLimit:
		log.WarnContext(ctx, "relay ended: limit exceeded",
			"user", result.LoginName,
			"close_reason", relayResult.Reason,
			"initiated_by", relayResult.InitiatedBy,
			"error", relayResult.Err,
		)
	case restrict.CloseNetwork:
		log.WarnContext(ctx, "relay ended: network error",
			"user", result.LoginName,
			"initiated_by", relayResult.InitiatedBy,
			"error", relayResult.Err,
		)
	}

	// Record aggregate byte counters for heartbeat after relay completes.
	// OTel byte metrics are reported incrementally by ConnLimits.flush().
	br, bw := cl.BytesRead(), cl.BytesWritten()
	if p.BytesRead != nil {
		p.BytesRead.Add(br)
	}
	if p.BytesWritten != nil {
		p.BytesWritten.Add(bw)
	}

	// Close span — linked to setup for correlation.
	_, closeSpan := tracer.Start(ctx, "waypoint.connection.close",
		trace.WithLinks(trace.Link{SpanContext: setupSpanCtx}),
		trace.WithAttributes(
			attribute.String("waypoint.conn_id", connID),
			attribute.String("waypoint.listener", p.Name),
			attribute.String("waypoint.user", result.LoginName),
			attribute.Int64("waypoint.bytes_read", br),
			attribute.Int64("waypoint.bytes_written", bw),
			attribute.Float64("waypoint.duration_s", time.Since(connStart).Seconds()),
			attribute.String("waypoint.close_reason", string(relayResult.Reason)),
			attribute.String("waypoint.close_initiated_by", string(relayResult.InitiatedBy)),
		),
	)
	closeSpan.End()

	log.InfoContext(ctx, "connection closed",
		"duration", time.Since(connStart),
		"bytes_read", br,
		"bytes_written", bw,
		"close_reason", relayResult.Reason,
		"initiated_by", relayResult.InitiatedBy,
	)
}

// revalidateLoop periodically re-checks WhoIs + caps and reconciles the active
// backend role to match current permissions.
func (p *PostgresProxy) revalidateLoop(ctx context.Context, setupSpanCtx trace.SpanContext, connID string, clientConn, backendConn net.Conn, loginName, database, pgUser string, presetLimit *postgresPresetLimit, log *slog.Logger) {
	ticker := time.NewTicker(p.RevalInterval)
	defer ticker.Stop()

	m := p.Metrics
	tracer := m.Tracer()
	listenerAttr := metrics.AttrListener.String(p.Name)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.DebugContext(ctx, "revalidation check")
			m.RevalAttempts.Add(ctx, 1, m.Attrs("waypoint.reval.attempts", listenerAttr))

			_, revalSpan := tracer.Start(ctx, "waypoint.revalidation",
				trace.WithLinks(trace.Link{SpanContext: setupSpanCtx}),
				trace.WithAttributes(
					attribute.String("waypoint.conn_id", connID),
					attribute.String("waypoint.listener", p.Name),
					attribute.String("waypoint.user", loginName),
				),
			)

			result, err := p.Auth.Authorize(ctx, clientConn.RemoteAddr().String(), p.Name)
			if err != nil {
				revalSpan.RecordError(err)
				revalSpan.SetStatus(codes.Error, "revalidation failed")
				revalSpan.End()
				m.RevalFailures.Add(ctx, 1, m.Attrs("waypoint.reval.failures", listenerAttr))
				log.WarnContext(ctx, "revalidation failed, closing connection",
					"user", loginName,
					"error", err,
				)
				clientConn.Close()
				backendConn.Close()
				return
			}

			var dbPerms *auth.DBPermissions
			if currentPerms := auth.DatabasePermissions(result, p.Name, database); currentPerms != nil {
				dbPerms = currentPerms
				if presetLimit != nil {
					var effectivePreset string
					var err error
					dbPerms, effectivePreset, err = limitDBPermissionsToPostgresPreset(dbPerms, presetLimit)
					if err != nil {
						revalSpan.RecordError(err)
						log.WarnContext(ctx, "preset limit no longer satisfied; reconciling active role with no grants",
							"user", loginName,
							"database", database,
							"preset_limit", presetLimit.Raw,
							"error", err,
						)
						dbPerms = nil
					} else {
						revalSpan.SetAttributes(attribute.String("waypoint.effective_preset", effectivePreset))
					}
				}
			}

			provStart := time.Now()
			m.ProvisionTotal.Add(ctx, 1, m.Attrs("waypoint.provision.total", listenerAttr))
			if err := p.Provisioner.ReconcileRole(ctx, pgUser, database, dbPerms); err != nil {
				m.ProvisionLatency.Record(ctx, time.Since(provStart).Seconds(),
					m.Attrs("waypoint.provision.latency", listenerAttr))
				m.ProvisionErrors.Add(ctx, 1, m.Attrs("waypoint.provision.errors", listenerAttr))
				revalSpan.RecordError(err)
				revalSpan.SetStatus(codes.Error, "reconcile permissions failed")
				revalSpan.End()
				m.RevalFailures.Add(ctx, 1, m.Attrs("waypoint.reval.failures", listenerAttr))
				log.WarnContext(ctx, "permission reconciliation failed, closing connection",
					"user", loginName,
					"database", database,
					"pg_user", pgUser,
					"error", err,
				)
				clientConn.Close()
				backendConn.Close()
				return
			}
			m.ProvisionLatency.Record(ctx, time.Since(provStart).Seconds(),
				m.Attrs("waypoint.provision.latency", listenerAttr))

			if dbPerms == nil {
				log.WarnContext(ctx, "permissions revoked; active role reconciled with no grants",
					"user", loginName,
					"database", database,
					"pg_user", pgUser,
				)
			} else {
				log.DebugContext(ctx, "permissions reconciled",
					"user", loginName,
					"database", database,
					"pg_user", pgUser,
					"permissions", dbPerms.Permissions,
				)
			}

			revalSpan.End()
			log.DebugContext(ctx, "revalidation passed")
		}
	}
}
