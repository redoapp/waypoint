package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// BandwidthTier defines a byte budget over a time period.
type BandwidthTier struct {
	Bytes  int64
	Period time.Duration
}

// MergedLimits holds the resolved limits after merging all matching rules.
type MergedLimits struct {
	MaxConns        int
	MaxBytesPerConn int64
	MaxConnDuration time.Duration
	BandwidthTiers  []BandwidthTier
}

// Authorize checks the caller's Tailscale identity and capability grants
// for the given backend listener name.
func Authorize(ctx context.Context, lc *local.Client, remoteAddr string, backend string, logger *slog.Logger) (*AuthResult, error) {
	logger.Debug("WhoIs lookup", "remote", remoteAddr)
	who, err := lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("WhoIs failed: %w", err)
	}
	if who.UserProfile == nil {
		return nil, errors.New("no user profile in WhoIs response")
	}

	nodeName := who.Node.ComputedName
	if nodeName == "" && len(who.Node.Name) > 0 {
		nodeName = strings.Split(who.Node.Name, ".")[0]
	}

	logger.Info("WhoIs identity",
		"login", who.UserProfile.LoginName,
		"node", nodeName,
		"remote", remoteAddr,
	)

	rules, err := tailcfg.UnmarshalCapJSON[CapRule](who.CapMap, WaypointCap)
	if err != nil {
		return nil, fmt.Errorf("unmarshal capabilities: %w", err)
	}
	if len(rules) == 0 {
		logger.Info("access denied: no capability rules",
			"login", who.UserProfile.LoginName,
			"node", nodeName,
			"cap", WaypointCap,
		)
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
		var availableBackends []string
		seen := make(map[string]bool)
		for _, r := range rules {
			for _, b := range r.Backends {
				if !seen[b] {
					availableBackends = append(availableBackends, b)
					seen[b] = true
				}
			}
		}
		logger.Info("access denied: no rules for backend",
			"login", who.UserProfile.LoginName,
			"node", nodeName,
			"backend", backend,
			"available_backends", availableBackends,
		)
		return nil, fmt.Errorf("not authorized for backend %q", backend)
	}

	perms, limits := mergeRules(matched)

	logger.Debug("capability rules matched",
		"rules_matched", len(matched),
		"permissions", perms,
	)

	var limitAttrs []any
	if limits.MaxConns > 0 {
		limitAttrs = append(limitAttrs, "max_conns", limits.MaxConns)
	}
	if limits.MaxBytesPerConn > 0 {
		limitAttrs = append(limitAttrs, "max_bytes_per_conn", limits.MaxBytesPerConn)
	}
	if limits.MaxConnDuration > 0 {
		limitAttrs = append(limitAttrs, "max_conn_duration", limits.MaxConnDuration)
	}
	if len(limits.BandwidthTiers) > 0 {
		limitAttrs = append(limitAttrs, "bandwidth_tiers", len(limits.BandwidthTiers))
	}
	if len(limitAttrs) > 0 {
		logger.Debug("effective limits", limitAttrs...)
	}

	return &AuthResult{
		LoginName:    who.UserProfile.LoginName,
		NodeName:     nodeName,
		Permissions:  perms,
		Limits:       limits,
		MatchedRules: matched,
	}, nil
}

// DatabasePermissions returns the merged permissions for a specific database
// from the matched rules. Returns nil if no rules grant access to the database.
func DatabasePermissions(result *AuthResult, database string) *DBPermissions {
	var perms []string
	var sql []string
	found := false

	for _, r := range result.MatchedRules {
		if r.PG == nil {
			continue
		}
		// Check for exact database match.
		if db, ok := r.PG.Databases[database]; ok {
			perms = append(perms, db.Permissions...)
			sql = append(sql, db.SQL...)
			found = true
		}
		// Check for wildcard.
		if db, ok := r.PG.Databases["*"]; ok {
			perms = append(perms, db.Permissions...)
			sql = append(sql, db.SQL...)
			found = true
		}
	}

	if !found {
		return nil
	}
	return &DBPermissions{
		Permissions: perms,
		SQL:         sql,
	}
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
	for _, bw := range cap.Bandwidth {
		period, err := time.ParseDuration(bw.Period)
		if err != nil || bw.Bytes <= 0 || period <= 0 {
			continue
		}
		// Dedup by period: keep the most restrictive bytes for the same period.
		found := false
		for i := range merged.BandwidthTiers {
			if merged.BandwidthTiers[i].Period == period {
				if bw.Bytes < merged.BandwidthTiers[i].Bytes {
					merged.BandwidthTiers[i].Bytes = bw.Bytes
				}
				found = true
				break
			}
		}
		if !found {
			merged.BandwidthTiers = append(merged.BandwidthTiers, BandwidthTier{
				Bytes:  bw.Bytes,
				Period: period,
			})
		}
	}
}
