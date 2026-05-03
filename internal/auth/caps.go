package auth

import "encoding/json"

const WaypointCap = "redo.com/cap/waypoint"

// CapRule represents a single capability rule from the Tailscale ACL grant.
// Top-level Limits apply globally (per-user across all backends).
// Each backend entry in Backends carries its own PG and Limits (per-endpoint).
type CapRule struct {
	Limits   *LimitsCap            `json:"limits,omitempty"`
	Backends map[string]BackendCap `json:"backends"`
}

// BackendCap holds per-backend capabilities and limits.
type BackendCap struct {
	PG     *PGCap     `json:"pg,omitempty"`
	Limits *LimitsCap `json:"limits,omitempty"`
}

// PGCap holds postgres-specific capabilities.
type PGCap struct {
	Databases map[string]DBPermissions `json:"databases"`
}

// DBPermissions defines access grants for a database.
// Permissions holds preset names ("readonly", "readwrite", "admin").
// Schemas controls which schemas presets apply to (default: ["public"]).
// SQL holds advanced raw SQL templates (gateable by server config).
// SQL entries are Go text/template strings. Available variables:
//   - {{.Role}} — the sanitized PG role identifier for the connecting user
type DBPermissions struct {
	Permissions []string `json:"permissions"`
	Schemas     []string `json:"schemas,omitempty"`
	SQL         []string `json:"sql,omitempty"`
}

// LimitsCap defines per-user restriction overrides from ACL grants.
type LimitsCap struct {
	MaxConns        int            `json:"max_conns,omitempty"`
	MaxBytesPerConn int64          `json:"max_bytes_per_conn,omitempty"`
	MaxConnDuration string         `json:"max_conn_duration,omitempty"`
	Bandwidth       []BandwidthCap `json:"bandwidth,omitempty"`
}

// BandwidthCap defines a byte budget over a time period.
type BandwidthCap struct {
	Bytes  int64  `json:"bytes"`
	Period string `json:"period"`
}

// UnmarshalJSON supports both the current schema (backends as a map) and the
// legacy schema (backends as a string array with top-level pg/endpoint_limits).
func (c *CapRule) UnmarshalJSON(data []byte) error {
	// Try new format first (backends is an object).
	type capRuleNew CapRule
	var newFmt capRuleNew
	if err := json.Unmarshal(data, &newFmt); err == nil && newFmt.Backends != nil {
		*c = CapRule(newFmt)
		return nil
	}

	// Fall back to legacy format (backends is a string array).
	var legacy struct {
		Backends       []string              `json:"backends"`
		PG             *PGCap                `json:"pg,omitempty"`
		Limits         *LimitsCap            `json:"limits,omitempty"`
		EndpointLimits map[string]*LimitsCap `json:"endpoint_limits,omitempty"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}

	c.Limits = legacy.Limits
	c.Backends = make(map[string]BackendCap, len(legacy.Backends))
	for _, b := range legacy.Backends {
		bc := BackendCap{PG: legacy.PG}
		if ep, ok := legacy.EndpointLimits[b]; ok {
			bc.Limits = ep
		}
		c.Backends[b] = bc
	}
	return nil
}
