package auth

const WaypointCap = "redo.com/cap/waypoint"

// CapRule represents a single capability rule from the Tailscale ACL grant.
type CapRule struct {
	Backends []string   `json:"backends"`
	PG       *PGCap     `json:"pg,omitempty"`
	Limits   *LimitsCap `json:"limits,omitempty"`
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
