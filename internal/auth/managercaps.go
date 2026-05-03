package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
)

const WaypointManagerCap = "redo.com/cap/waypointManager"

// ManagerCapRule represents a capability rule for the waypoint manager.
type ManagerCapRule struct {
	// Future: could scope permissions (read-only vs read-write).
}

// ManagerAuthResult is returned after successful manager authorization.
type ManagerAuthResult struct {
	LoginName string
	NodeName  string
}

// AuthorizeManager checks whether the caller has the waypointManager capability.
func AuthorizeManager(ctx context.Context, lc *local.Client, remoteAddr string, logger *slog.Logger) (*ManagerAuthResult, error) {
	tracer := otel.Tracer("waypoint")

	logger.DebugContext(ctx, "WhoIs lookup", "remote", remoteAddr)
	ctx, whoIsSpan := tracer.Start(ctx, "tailscale.whois",
		trace.WithAttributes(attribute.String("peer.service", "tailscale")),
	)
	who, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		whoIsSpan.RecordError(err)
		whoIsSpan.SetStatus(codes.Error, "WhoIs failed")
		whoIsSpan.End()
		return nil, fmt.Errorf("WhoIs failed: %w", err)
	}
	whoIsSpan.End()
	if who.UserProfile == nil {
		return nil, errors.New("no user profile in WhoIs response")
	}

	nodeName := who.Node.ComputedName
	if nodeName == "" && len(who.Node.Name) > 0 {
		nodeName = strings.Split(who.Node.Name, ".")[0]
	}

	logger.InfoContext(ctx, "WhoIs identity",
		"login", who.UserProfile.LoginName,
		"node", nodeName,
	)

	rules, err := tailcfg.UnmarshalCapJSON[ManagerCapRule](who.CapMap, WaypointManagerCap)
	if err != nil {
		return nil, fmt.Errorf("unmarshal manager capabilities: %w", err)
	}
	if len(rules) == 0 {
		logger.InfoContext(ctx, "manager access denied: no capability rules",
			"login", who.UserProfile.LoginName,
			"node", nodeName,
		)
		return nil, errors.New("not authorized for waypoint manager access")
	}

	return &ManagerAuthResult{
		LoginName: who.UserProfile.LoginName,
		NodeName:  nodeName,
	}, nil
}
