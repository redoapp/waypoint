package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
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
	RevalInterval time.Duration
	Logger        *slog.Logger
	Dialer        func(ctx context.Context, network, addr string) (net.Conn, error)
	BytesRead     *atomic.Int64 // optional: aggregate byte counter
	BytesWritten  *atomic.Int64 // optional: aggregate byte counter
}

// HandleConn processes a single inbound PostgreSQL connection.
func (p *PostgresProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	m := p.Metrics
	listenerAttr := metrics.AttrListener.String(p.Name)
	modeAttr := metrics.AttrMode.String("postgres")

	// Step 1: Authorize via Tailscale identity.
	m.AuthAttempts.Add(ctx, 1, m.Attrs("waypoint.auth.attempts", listenerAttr))
	authStart := time.Now()
	result, err := p.Auth.Authorize(ctx, clientConn.RemoteAddr().String(), p.Name)
	authDur := time.Since(authStart).Seconds()
	m.AuthLatency.Record(ctx, authDur, m.Attrs("waypoint.auth.latency", listenerAttr))
	if err != nil {
		m.AuthFailures.Add(ctx, 1, m.Attrs("waypoint.auth.failures", listenerAttr))
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		p.Logger.Warn("auth failed", "remote", clientConn.RemoteAddr(), "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "28000", "authentication failed: "+err.Error())
		return
	}

	p.Logger.Info("authorized",
		"user", result.LoginName,
		"node", result.NodeName,
		"backend", p.Name,
	)

	// Step 2: Acquire connection slot.
	release, err := p.Tracker.Acquire(ctx, result.LoginName, result.Limits)
	if err != nil {
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		p.Logger.Warn("limit exceeded", "user", result.LoginName, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "53300", "too many connections: "+err.Error())
		return
	}
	defer release()

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
		p.Logger.Error("read startup failed", "error", err)
		return
	}

	requestedDB := startup.Parameters["database"]
	if requestedDB == "" {
		requestedDB = startup.Parameters["user"]
	}

	// Step 4: Check per-database permissions from cap rules.
	dbPerms := auth.DatabasePermissions(result, requestedDB)
	if dbPerms == nil {
		p.Logger.Warn("no permissions for database",
			"user", result.LoginName,
			"database", requestedDB,
		)
		pgwire.SendErrorResponse(clientConn, "FATAL", "42501",
			"not authorized for database "+requestedDB)
		return
	}

	// Step 5: Provision dynamic PG user.
	provStart := time.Now()
	m.ProvisionTotal.Add(ctx, 1, m.Attrs("waypoint.provision.total", listenerAttr))
	pgUser, pgPass, err := p.Provisioner.EnsureUser(ctx, result.LoginName, result.NodeName, requestedDB, dbPerms)
	m.ProvisionLatency.Record(ctx, time.Since(provStart).Seconds(),
		m.Attrs("waypoint.provision.latency", listenerAttr))
	if err != nil {
		m.ProvisionErrors.Add(ctx, 1, m.Attrs("waypoint.provision.errors", listenerAttr))
		p.Logger.Error("provision failed",
			"user", result.LoginName,
			"database", requestedDB,
			"error", err,
		)
		pgwire.SendErrorResponse(clientConn, "FATAL", "58000", "internal error")
		return
	}

	// Step 6: Connect to upstream PG with provisioned credentials.
	var backendConn net.Conn
	if p.Dialer != nil {
		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		defer dialCancel()
		backendConn, err = p.Dialer(dialCtx, "tcp", p.Backend)
	} else {
		backendConn, err = net.DialTimeout("tcp", p.Backend, 10*time.Second)
	}
	if err != nil {
		p.Logger.Error("backend dial failed", "backend", p.Backend, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "08006", "backend unavailable")
		return
	}
	defer backendConn.Close()

	// Step 7: Send startup to upstream with provisioned user.
	if err := pgwire.WriteStartupMessage(backendConn, pgUser, requestedDB, nil); err != nil {
		p.Logger.Error("send startup failed", "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "08006", "backend error")
		return
	}

	// Step 8: Handle upstream auth.
	upstreamFE, err := pgwire.HandleUpstreamAuth(backendConn, pgUser, pgPass)
	if err != nil {
		p.Logger.Error("upstream auth failed", "user", pgUser, "error", err)
		pgwire.SendErrorResponse(clientConn, "FATAL", "28P01", "backend authentication failed")
		return
	}

	// Step 9: Send AuthenticationOk to client (Tailscale identity = their credential).
	if err := pgwire.SendAuthOK(clientConn); err != nil {
		p.Logger.Error("send auth ok failed", "error", err)
		return
	}

	// Step 10: Forward post-auth messages (ParameterStatus, BackendKeyData, ReadyForQuery).
	if err := pgwire.ForwardPostAuth(upstreamFE, clientConn); err != nil {
		p.Logger.Error("forward post-auth failed", "error", err)
		return
	}

	// Step 11: Bidirectional relay with limits.
	cl := p.Tracker.WrapConn(ctx, result.LoginName, result.Limits)

	// Step 12: Start mid-session revalidation.
	revalCtx, revalCancel := context.WithCancel(ctx)
	defer revalCancel()
	if p.RevalInterval > 0 {
		go p.revalidateLoop(revalCtx, clientConn, backendConn, result.LoginName, requestedDB)
	}

	if err := restrict.Relay(clientConn, backendConn, cl); err != nil {
		p.Logger.Debug("relay ended", "user", result.LoginName, "error", err)
	}

	// Record byte counters after relay completes.
	br, bw := cl.BytesRead(), cl.BytesWritten()
	m.BytesRead.Add(ctx, br, m.Attrs("waypoint.bytes.read", listenerAttr))
	m.BytesWritten.Add(ctx, bw, m.Attrs("waypoint.bytes.written", listenerAttr))
	if p.BytesRead != nil {
		p.BytesRead.Add(br)
	}
	if p.BytesWritten != nil {
		p.BytesWritten.Add(bw)
	}
}

// revalidateLoop periodically re-checks WhoIs + caps. Closes connections
// if the user's grant is revoked.
func (p *PostgresProxy) revalidateLoop(ctx context.Context, clientConn, backendConn net.Conn, loginName, database string) {
	ticker := time.NewTicker(p.RevalInterval)
	defer ticker.Stop()

	m := p.Metrics
	listenerAttr := metrics.AttrListener.String(p.Name)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.RevalAttempts.Add(ctx, 1, m.Attrs("waypoint.reval.attempts", listenerAttr))
			result, err := p.Auth.Authorize(ctx, clientConn.RemoteAddr().String(), p.Name)
			if err != nil {
				m.RevalFailures.Add(ctx, 1, m.Attrs("waypoint.reval.failures", listenerAttr))
				p.Logger.Warn("revalidation failed, closing connection",
					"user", loginName,
					"error", err,
				)
				clientConn.Close()
				backendConn.Close()
				return
			}

			dbPerms := auth.DatabasePermissions(result, database)
			if dbPerms == nil {
				m.RevalFailures.Add(ctx, 1, m.Attrs("waypoint.reval.failures", listenerAttr))
				p.Logger.Warn("permissions revoked, closing connection",
					"user", loginName,
					"database", database,
				)
				clientConn.Close()
				backendConn.Close()
				return
			}
		}
	}
}
