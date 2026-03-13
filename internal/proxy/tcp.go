package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
	"tailscale.com/client/local"
)

// TCPProxy handles raw TCP proxying with Tailscale auth and limits.
type TCPProxy struct {
	Backend      string
	Name         string
	LC           *local.Client
	Tracker      *restrict.Tracker
	Metrics      *metrics.Metrics
	Logger       *slog.Logger
	BytesRead    *atomic.Int64 // optional: aggregate byte counter
	BytesWritten *atomic.Int64 // optional: aggregate byte counter
}

// HandleConn processes a single inbound TCP connection.
func (p *TCPProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	m := p.Metrics
	listenerAttr := metrics.AttrListener.String(p.Name)
	modeAttr := metrics.AttrMode.String("tcp")

	// Auth.
	m.AuthAttempts.Add(ctx, 1, m.Attrs("waypoint.auth.attempts", listenerAttr))
	authStart := time.Now()
	result, err := auth.Authorize(ctx, p.LC, clientConn.RemoteAddr().String(), p.Name)
	authDur := time.Since(authStart).Seconds()
	m.AuthLatency.Record(ctx, authDur, m.Attrs("waypoint.auth.latency", listenerAttr))
	if err != nil {
		m.AuthFailures.Add(ctx, 1, m.Attrs("waypoint.auth.failures", listenerAttr))
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		p.Logger.Warn("auth failed", "remote", clientConn.RemoteAddr(), "error", err)
		return
	}

	p.Logger.Info("authorized",
		"user", result.LoginName,
		"node", result.NodeName,
		"backend", p.Name,
	)

	// Acquire connection slot.
	release, err := p.Tracker.Acquire(ctx, result.LoginName, result.Limits)
	if err != nil {
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		p.Logger.Warn("limit exceeded", "user", result.LoginName, "error", err)
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

	backendConn, err := net.DialTimeout("tcp", p.Backend, 10*time.Second)
	if err != nil {
		p.Logger.Error("backend dial failed", "backend", p.Backend, "error", err)
		return
	}
	defer backendConn.Close()

	cl := p.Tracker.WrapConn(ctx, result.LoginName, result.Limits)

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
