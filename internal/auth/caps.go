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

// DBPermissions lists SQL GRANT statements for a database.
type DBPermissions struct {
	Permissions []string `json:"permissions"`
}

// LimitsCap defines per-user restriction overrides from ACL grants.
type LimitsCap struct {
	MaxConns        int           `json:"max_conns,omitempty"`
	MaxBytesPerConn int64         `json:"max_bytes_per_conn,omitempty"`
	MaxConnDuration string        `json:"max_conn_duration,omitempty"`
	Bandwidth       *BandwidthCap `json:"bandwidth,omitempty"`
}

// BandwidthCap defines a byte budget over a time period.
type BandwidthCap struct {
	Bytes  int64  `json:"bytes"`
	Period string `json:"period"`
}
