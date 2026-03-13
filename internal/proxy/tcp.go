package proxy

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/restrict"
	"tailscale.com/client/local"
)

// TCPProxy handles raw TCP proxying with Tailscale auth and limits.
type TCPProxy struct {
	Backend string
	Name    string
	LC      *local.Client
	Tracker *restrict.Tracker
	Logger  *slog.Logger
}

// HandleConn processes a single inbound TCP connection.
func (p *TCPProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	result, err := auth.Authorize(ctx, p.LC, clientConn.RemoteAddr().String(), p.Name)
	if err != nil {
		p.Logger.Warn("auth failed", "remote", clientConn.RemoteAddr(), "error", err)
		return
	}

	p.Logger.Info("authorized",
		"user", result.LoginName,
		"node", result.NodeName,
		"backend", p.Name,
	)

	release, err := p.Tracker.Acquire(ctx, result.LoginName, result.Limits)
	if err != nil {
		p.Logger.Warn("limit exceeded", "user", result.LoginName, "error", err)
		return
	}
	defer release()

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
}
