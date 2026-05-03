package proxy

import (
	"context"
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
	BackendTLS    bool
	RevalInterval time.Duration
	Logger        *slog.Logger
	Dialer        func(ctx context.Context, network, addr string) (net.Conn, error)
	BytesRead     *atomic.Int64 // optional: aggregate byte counter
	BytesWritten  *atomic.Int64 // optional: aggregate byte counter
}

// HandleConn processes a single inbound PostgreSQL connection.
func (p *PostgresProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	connID := logging.NewConnID()
	log := p.Logger.With("conn_id", connID, "remote", clientConn.RemoteAddr())
	log.Debug("connection accepted")

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
		log.Warn("auth failed", "error", err, "listener", p.Name)
		pgwire.SendErrorResponse(clientConn, "FATAL", "28000", "authentication failed: "+err.Error())
		return
	}
	authSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	authSpan.End()

	log.Info("authorized",
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
		log.Warn("limit exceeded", "user", result.LoginName, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "53300", "too many connections: "+err.Error())
		return
	}
	slotSpan.End()
	defer release()
	log.Debug("connection slot acquired")

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
	startup, err := pgwire.ReadStartupMessage(clientConn)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "read startup failed")
		setupSpan.End()
		log.Error("read startup failed", "error", err)
		return
	}

	requestedDB := startup.Parameters["database"]
	if requestedDB == "" {
		requestedDB = startup.Parameters["user"]
	}

	log.Debug("startup message received", "database", requestedDB)
	setupSpan.SetAttributes(attribute.String("waypoint.database", requestedDB))

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
		log.Warn("no permissions for database",
			"user", result.LoginName,
			"database", requestedDB,
			"granted_databases", grantedDBs,
		)
		pgwire.SendErrorResponse(clientConn, "FATAL", "42501",
			"not authorized for database "+requestedDB)
		return
	}

	log.Debug("database permissions resolved",
		"database", requestedDB,
		"permissions", dbPerms.Permissions,
		"sql_count", len(dbPerms.SQL),
	)

	// Step 5: Provision dynamic PG user.
	provStart := time.Now()
	m.ProvisionTotal.Add(ctx, 1, m.Attrs("waypoint.provision.total", listenerAttr))
	ctx, provSpan := tracer.Start(ctx, "waypoint.provision")
	pgUser, pgPass, err := p.Provisioner.EnsureUser(ctx, result.LoginName, result.NodeName, requestedDB, dbPerms)
	provSpan.End()
	m.ProvisionLatency.Record(ctx, time.Since(provStart).Seconds(),
		m.Attrs("waypoint.provision.latency", listenerAttr))
	if err != nil {
		m.ProvisionErrors.Add(ctx, 1, m.Attrs("waypoint.provision.errors", listenerAttr))
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "provision failed")
		setupSpan.End()
		log.Error("provision failed",
			"user", result.LoginName,
			"database", requestedDB,
			"error", err,
		)
		pgwire.SendErrorResponse(clientConn, "FATAL", "58000", "internal error")
		return
	}

	log.Debug("user provisioned", "pg_user", pgUser, "database", requestedDB)

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
		log.Error("backend dial failed", "backend", p.Backend, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "08006", "backend unavailable")
		return
	}
	dialSpan.End()
	defer backendConn.Close()

	log.Debug("backend connected")

	// Step 6b: Upgrade to TLS if configured.
	if p.BackendTLS {
		backendConn, err = pgwire.UpgradeToTLS(backendConn)
		if err != nil {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "backend TLS failed")
			setupSpan.End()
			log.Error("backend TLS upgrade failed", "error", err)
			pgwire.SendErrorResponse(clientConn, "FATAL", "08006", "backend TLS failed")
			return
		}
		log.Debug("backend TLS established")
	}

	// Step 7: Send startup to upstream with provisioned user.
	if err := pgwire.WriteStartupMessage(backendConn, pgUser, requestedDB, nil); err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "send startup failed")
		setupSpan.End()
		log.Error("send startup failed", "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "08006", "backend error")
		return
	}

	// Step 8: Handle upstream auth.
	upstreamFE, err := pgwire.HandleUpstreamAuth(backendConn, pgUser, pgPass)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "upstream auth failed")
		setupSpan.End()
		log.Error("upstream auth failed", "user", pgUser, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "28P01", "backend authentication failed")
		return
	}

	log.Debug("upstream auth complete")

	// Step 9: Send AuthenticationOk to client (Tailscale identity = their credential).
	if err := pgwire.SendAuthOK(clientConn); err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "send auth ok failed")
		setupSpan.End()
		log.Error("send auth ok failed", "error", err)
		return
	}

	// Step 10: Forward post-auth messages (ParameterStatus, BackendKeyData, ReadyForQuery).
	if err := pgwire.ForwardPostAuth(upstreamFE, clientConn); err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "forward post-auth failed")
		setupSpan.End()
		log.Error("forward post-auth failed", "error", err)
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
		go p.revalidateLoop(revalCtx, setupSpanCtx, connID, clientConn, backendConn, result.LoginName, requestedDB, log)
	}

	log.Debug("relay started")

	if err := restrict.Relay(clientConn, backendConn, cl); err != nil {
		log.Debug("relay ended", "user", result.LoginName, "error", err)
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
		),
	)
	closeSpan.End()

	log.Info("connection closed", "duration", time.Since(connStart), "bytes_read", br, "bytes_written", bw)
}

// revalidateLoop periodically re-checks WhoIs + caps. Closes connections
// if the user's grant is revoked.
func (p *PostgresProxy) revalidateLoop(ctx context.Context, setupSpanCtx trace.SpanContext, connID string, clientConn, backendConn net.Conn, loginName, database string, log *slog.Logger) {
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
			log.Debug("revalidation check")
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
				log.Warn("revalidation failed, closing connection",
					"user", loginName,
					"error", err,
				)
				clientConn.Close()
				backendConn.Close()
				return
			}

			dbPerms := auth.DatabasePermissions(result, p.Name, database)
			if dbPerms == nil {
				revalSpan.SetStatus(codes.Error, "permissions revoked")
				revalSpan.End()
				m.RevalFailures.Add(ctx, 1, m.Attrs("waypoint.reval.failures", listenerAttr))
				log.Warn("permissions revoked, closing connection",
					"user", loginName,
					"database", database,
				)
				clientConn.Close()
				backendConn.Close()
				return
			}

			revalSpan.End()
			log.Debug("revalidation passed")
		}
	}
}
