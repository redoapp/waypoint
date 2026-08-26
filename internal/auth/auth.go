package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redoapp/waypoint/internal/querylog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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

	// QueryLog is the level the matched ACL grants asked for, or nil when no
	// grant mentioned logging. Nil means "defer to the listener default"; the
	// proxy applies the listener's ceiling on top either way.
	QueryLog *querylog.Level
}

// BandwidthTier defines a byte budget over a time period.
type BandwidthTier struct {
	Bytes  int64
	Period time.Duration
}

// MergedLimits holds the resolved limits after merging all matching rules.
type MergedLimits struct {
	// Per-user (global) limits — checked against root key (waypoint:conns:<user>).
	MaxConns        int
	MaxBytesPerConn int64
	MaxConnDuration time.Duration
	BandwidthTiers  []BandwidthTier

	// Per-endpoint limits — checked against leaf key (waypoint:conns:<user>/<listener>).
	// Nil means no endpoint-specific limits (only global apply).
	Endpoint *EndpointLimits
}

// EndpointLimits holds per-endpoint restriction overrides.
type EndpointLimits struct {
	MaxConns        int
	MaxBytesPerConn int64
	MaxConnDuration time.Duration
	BandwidthTiers  []BandwidthTier
}

// Authorize checks the caller's Tailscale identity and capability grants
// for the given backend listener name.
func Authorize(ctx context.Context, lc *local.Client, remoteAddr string, backend string, logger *slog.Logger) (*AuthResult, error) {
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
		"display_name", who.UserProfile.DisplayName,
		"user_id", who.UserProfile.ID,
		"node", nodeName,
		"node_id", who.Node.ID,
		"node_stable_id", who.Node.StableID,
		"tags", who.Node.Tags,
		"remote", remoteAddr,
	)

	rules, err := tailcfg.UnmarshalCapJSON[CapRule](who.CapMap, WaypointCap)
	if err != nil {
		return nil, fmt.Errorf("unmarshal capabilities: %w", err)
	}
	if len(rules) == 0 {
		// Collect all capability keys the peer has for diagnostics.
		var peerCaps []string
		for cap := range who.CapMap {
			peerCaps = append(peerCaps, string(cap))
		}

		logger.InfoContext(ctx, "access denied: no capability rules",
			"login", who.UserProfile.LoginName,
			"display_name", who.UserProfile.DisplayName,
			"node", nodeName,
			"tags", who.Node.Tags,
			"cap", WaypointCap,
			"backend", backend,
			"peer_caps", peerCaps,
		)
		return nil, fmt.Errorf(
			"no %s capability rules for user %s (node %s, tags %v); ensure a Tailscale ACL grant assigns this capability to the destination service",
			WaypointCap, who.UserProfile.LoginName, nodeName, who.Node.Tags,
		)
	}

	// Filter rules matching the requested backend and merge.
	var matched []CapRule
	for _, r := range rules {
		if _, ok := r.Backends[backend]; ok {
			matched = append(matched, r)
		}
	}
	if len(matched) == 0 {
		var availableBackends []string
		seen := make(map[string]bool)
		for _, r := range rules {
			for b := range r.Backends {
				if !seen[b] {
					availableBackends = append(availableBackends, b)
					seen[b] = true
				}
			}
		}
		logger.InfoContext(ctx, "access denied: no rules for backend",
			"login", who.UserProfile.LoginName,
			"node", nodeName,
			"backend", backend,
			"available_backends", availableBackends,
		)
		return nil, fmt.Errorf(
			"user %s (node %s) not authorized for backend %q; authorized backends: %v",
			who.UserProfile.LoginName, nodeName, backend, availableBackends,
		)
	}

	perms, limits, queryLog := mergeRules(matched, backend, logger)

	logger.DebugContext(ctx, "capability rules matched",
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
		logger.DebugContext(ctx, "effective limits", limitAttrs...)
	}

	return &AuthResult{
		LoginName:    who.UserProfile.LoginName,
		NodeName:     nodeName,
		Permissions:  perms,
		Limits:       limits,
		MatchedRules: matched,
		QueryLog:     queryLog,
	}, nil
}

// DatabasePermissions returns the merged permissions for a specific database
// from the matched rules for the given backend. Returns nil if no rules grant
// access to the database.
func DatabasePermissions(result *AuthResult, backend string, database string) *DBPermissions {
	var perms []string
	var schemas []string
	var sql []string
	found := false

	schemasSeen := make(map[string]bool)

	for _, r := range result.MatchedRules {
		bc, ok := r.Backends[backend]
		if !ok || bc.PG == nil {
			continue
		}
		// Check for exact database match.
		if db, ok := bc.PG.Databases[database]; ok {
			perms = append(perms, db.Permissions...)
			sql = append(sql, db.SQL...)
			for _, s := range db.Schemas {
				if !schemasSeen[s] {
					schemasSeen[s] = true
					schemas = append(schemas, s)
				}
			}
			found = true
		}
		// Check for wildcard.
		if db, ok := bc.PG.Databases["*"]; ok {
			perms = append(perms, db.Permissions...)
			sql = append(sql, db.SQL...)
			for _, s := range db.Schemas {
				if !schemasSeen[s] {
					schemasSeen[s] = true
					schemas = append(schemas, s)
				}
			}
			found = true
		}
	}

	if !found {
		return nil
	}
	return &DBPermissions{
		Permissions: perms,
		Schemas:     schemas,
		SQL:         sql,
	}
}

// MongoDatabasePermissions returns the merged MongoDB permissions for a specific
// database from the matched rules for the given backend. Returns nil if no
// rules grant access to the database.
func MongoDatabasePermissions(result *AuthResult, backend string, database string) *MongoDBPermissions {
	var perms []string
	found := false

	for _, r := range result.MatchedRules {
		bc, ok := r.Backends[backend]
		if !ok || bc.Mongo == nil {
			continue
		}
		if db, ok := bc.Mongo.Databases[database]; ok {
			perms = append(perms, db.Permissions...)
			found = true
		}
		if db, ok := bc.Mongo.Databases["*"]; ok {
			perms = append(perms, db.Permissions...)
			found = true
		}
	}

	if !found {
		return nil
	}
	return &MongoDBPermissions{
		Permissions: perms,
	}
}

// mergeRules collects all permissions and picks the most restrictive limits.
// backend is used to look up the BackendCap entry in each rule.
// mergeRules folds every rule matching backend into a single set of
// permissions, limits, and query log level.
func mergeRules(rules []CapRule, backend string, logger *slog.Logger) ([]string, MergedLimits, *querylog.Level) {
	var perms []string
	var limits MergedLimits
	var queryLog *querylog.Level

	for _, r := range rules {
		bc, ok := r.Backends[backend]
		if !ok {
			continue
		}
		if bc.PG != nil {
			for _, db := range bc.PG.Databases {
				perms = append(perms, db.Permissions...)
			}
		}
		if bc.Mongo != nil {
			for _, db := range bc.Mongo.Databases {
				perms = append(perms, db.Permissions...)
			}
		}
		if r.Limits != nil {
			mergeLimits(&limits, r.Limits)
		}
		if bc.Limits != nil {
			if limits.Endpoint == nil {
				limits.Endpoint = &EndpointLimits{}
			}
			mergeEndpointLimits(limits.Endpoint, bc.Limits)
		}

		// A backend-scoped logging cap wins over the top-level one, the same
		// way endpoint limits win over global limits.
		for _, cap := range []*LoggingCap{r.Logging, bc.Logging} {
			if lvl, ok := parseLoggingCap(cap, logger); ok {
				queryLog = mergeQueryLog(queryLog, lvl)
			}
		}
	}

	return perms, limits, queryLog
}

// parseLoggingCap reads a level out of a LoggingCap, warning and ignoring an
// unrecognized value rather than failing the connection — an ACL typo should
// not lock a user out of their database.
func parseLoggingCap(cap *LoggingCap, logger *slog.Logger) (querylog.Level, bool) {
	if cap == nil || cap.Queries == "" {
		return 0, false
	}
	lvl, err := querylog.ParseLevel(cap.Queries)
	if err != nil {
		if logger != nil {
			logger.Warn("ignoring unknown query log level in capability grant",
				"queries", cap.Queries, "error", err)
		}
		return 0, false
	}
	return lvl, true
}

// mergeQueryLog keeps the most verbose level across matching rules.
//
// Note this is the opposite of mergeLimits, which keeps the most restrictive
// value. The asymmetry is deliberate: for limits, "most restrictive" is the
// safe direction, and for auditing it is "most verbose" — adding a grant must
// never be able to quiet the record of what a user did. The listener's
// max_level is what bounds the result.
func mergeQueryLog(current *querylog.Level, candidate querylog.Level) *querylog.Level {
	if current == nil || candidate > *current {
		return &candidate
	}
	return current
}

// mergeEndpointLimits applies the most restrictive values from cap into endpoint limits.
func mergeEndpointLimits(merged *EndpointLimits, cap *LimitsCap) {
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
