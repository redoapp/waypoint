package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"
)

// AuthResult is returned after successful authorization.
type AuthResult struct {
	LoginName    string
	NodeName     string
	Permissions  []string // all merged PG permissions (across all databases)
	Limits       MergedLimits
	MatchedRules []CapRule // rules that matched the backend, for per-database lookup
}

// MergedLimits holds the resolved limits after merging all matching rules.
type MergedLimits struct {
	MaxConns        int
	MaxBytesPerConn int64
	MaxConnDuration time.Duration
	BandwidthBytes  int64
	BandwidthPeriod time.Duration
}

// Authorize checks the caller's Tailscale identity and capability grants
// for the given backend listener name.
func Authorize(ctx context.Context, lc *local.Client, remoteAddr string, backend string) (*AuthResult, error) {
	who, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("WhoIs failed: %w", err)
	}
	if who.UserProfile == nil {
		return nil, errors.New("no user profile in WhoIs response")
	}

	rules, err := tailcfg.UnmarshalCapJSON[CapRule](who.CapMap, WaypointCap)
	if err != nil {
		return nil, fmt.Errorf("unmarshal capabilities: %w", err)
	}
	if len(rules) == 0 {
		return nil, errors.New("not authorized for access to waypoint")
	}

	// Filter rules matching the requested backend and merge.
	var matched []CapRule
	for _, r := range rules {
		for _, b := range r.Backends {
			if b == backend {
				matched = append(matched, r)
				break
			}
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("not authorized for backend %q", backend)
	}

	perms, limits := mergeRules(matched)

	nodeName := who.Node.ComputedName
	if nodeName == "" && len(who.Node.Name) > 0 {
		nodeName = strings.Split(who.Node.Name, ".")[0]
	}

	return &AuthResult{
		LoginName:    who.UserProfile.LoginName,
		NodeName:     nodeName,
		Permissions:  perms,
		Limits:       limits,
		MatchedRules: matched,
	}, nil
}

// DatabasePermissions returns the merged SQL permissions for a specific database
// from the matched rules. Returns nil if no rules grant access to the database.
func DatabasePermissions(result *AuthResult, database string) []string {
	var perms []string
	found := false

	for _, r := range result.MatchedRules {
		if r.PG == nil {
			continue
		}
		// Check for exact database match.
		if db, ok := r.PG.Databases[database]; ok {
			perms = append(perms, db.Permissions...)
			found = true
		}
		// Check for wildcard.
		if db, ok := r.PG.Databases["*"]; ok {
			perms = append(perms, db.Permissions...)
			found = true
		}
	}

	if !found {
		return nil
	}
	return perms
}

// mergeRules collects all permissions and picks the most restrictive limits.
func mergeRules(rules []CapRule) ([]string, MergedLimits) {
	var perms []string
	var limits MergedLimits

	for _, r := range rules {
		if r.PG != nil {
			for _, db := range r.PG.Databases {
				perms = append(perms, db.Permissions...)
			}
		}
		if r.Limits != nil {
			mergeLimits(&limits, r.Limits)
		}
	}

	return perms, limits
}

// mergeLimits applies the most restrictive values from cap into merged.
func mergeLimits(merged *MergedLimits, cap *LimitsCap) {
	if cap.MaxConns > 0 && (merged.MaxConns == 0 || cap.MaxConns < merged.MaxConns) {
		merged.MaxConns = cap.MaxConns
	}
	if cap.MaxBytesPerConn > 0 && (merged.MaxBytesPerConn == 0 || cap.MaxBytesPerConn < merged.MaxBytesPerConn) {
		merged.MaxBytesPerConn = cap.MaxBytesPerConn
	}
	if cap.MaxConnDuration != "" {
		d, err := time.ParseDuration(cap.MaxConnDuration)
		if err == nil && d > 0 && (merged.MaxConnDuration == 0 || d < merged.MaxConnDuration) {
			merged.MaxConnDuration = d
		}
	}
	if cap.Bandwidth != nil {
		period, err := time.ParseDuration(cap.Bandwidth.Period)
		if err == nil && cap.Bandwidth.Bytes > 0 {
			if merged.BandwidthBytes == 0 || cap.Bandwidth.Bytes < merged.BandwidthBytes {
				merged.BandwidthBytes = cap.Bandwidth.Bytes
				merged.BandwidthPeriod = period
			}
		}
	}
}
