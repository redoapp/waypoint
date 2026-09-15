package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
)

// AuthorizeDelegation checks the transport peer for the dedicated delegation
// capability. Ordinary Waypoint database grants are deliberately ignored.
func AuthorizeDelegation(ctx context.Context, lc *local.Client, remoteAddr, backend string, logger *slog.Logger) (*TransportIdentity, error) {
	who, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("WhoIs failed: %w", err)
	}
	if who.UserProfile == nil {
		return nil, errors.New("no user profile in WhoIs response")
	}

	rules, err := tailcfg.UnmarshalCapJSON[DelegationCapRule](who.CapMap, WaypointDelegationCap)
	if err != nil {
		return nil, fmt.Errorf("unmarshal delegation capabilities: %w", err)
	}
	authorized := false
	for _, rule := range rules {
		if slices.Contains(rule.Backends, backend) {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, fmt.Errorf("transport peer is not authorized to delegate to backend %q", backend)
	}

	nodeName := who.Node.ComputedName
	if nodeName == "" && who.Node.Name != "" {
		nodeName = strings.Split(who.Node.Name, ".")[0]
	}
	logger.InfoContext(ctx, "delegation gateway authorized",
		"login", who.UserProfile.LoginName,
		"node", nodeName,
		"remote", remoteAddr,
		"backend", backend,
	)
	return &TransportIdentity{
		LoginName:  who.UserProfile.LoginName,
		NodeName:   nodeName,
		RemoteAddr: remoteAddr,
	}, nil
}
