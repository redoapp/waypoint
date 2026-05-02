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

	"github.com/redoapp/waypoint/internal/logging"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
)

// TCPProxy handles raw TCP proxying with Tailscale auth and limits.
type TCPProxy struct {
	Backend      string
	Name         string
	Auth         Authorizer
	Tracker      *restrict.Tracker
	Metrics      *metrics.Metrics
	Logger       *slog.Logger
	Dialer       func(ctx context.Context, network, addr string) (net.Conn, error)
	BytesRead    *atomic.Int64 // optional: aggregate byte counter
	BytesWritten *atomic.Int64 // optional: aggregate byte counter
}

// HandleConn processes a single inbound TCP connection.
func (p *TCPProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	connID := logging.NewConnID()
	log := p.Logger.With("conn_id", connID, "remote", clientConn.RemoteAddr())
	log.Debug("connection accepted")

	m := p.Metrics
	tracer := m.Tracer()
	listenerAttr := metrics.AttrListener.String(p.Name)
	modeAttr := metrics.AttrMode.String("tcp")

	// Setup span covers auth → acquire → dial.
	ctx, setupSpan := tracer.Start(ctx, "waypoint.connection.setup",
		trace.WithAttributes(
			attribute.String("waypoint.conn_id", connID),
			attribute.String("waypoint.listener", p.Name),
			attribute.String("waypoint.mode", "tcp"),
			attribute.String("waypoint.backend", p.Backend),
		),
	)
	setupSpanCtx := setupSpan.SpanContext()

	// Auth.
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
		return
	}
	authSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	authSpan.End()

	log.Info("authorized",
		"user", result.LoginName,
		"node", result.NodeName,
		"backend", p.Name,
	)

	// Acquire connection slot.
	ctx, slotSpan := tracer.Start(ctx, "waypoint.acquire_slot")
	release, err := p.Tracker.Acquire(ctx, result.LoginName, result.Limits)
	if err != nil {
		slotSpan.RecordError(err)
		slotSpan.SetStatus(codes.Error, "limit exceeded")
		slotSpan.End()
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "limit exceeded")
		setupSpan.End()
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		log.Warn("limit exceeded", "user", result.LoginName, "error", err)
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

	// Dial backend.
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
		return
	}
	dialSpan.End()
	defer backendConn.Close()

	// Setup complete — end the setup span before the long-lived relay.
	setupSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	setupSpan.End()

	cl := p.Tracker.WrapConn(ctx, result.LoginName, result.Limits, p.Name)

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
