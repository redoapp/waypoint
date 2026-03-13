package monitor

import "time"

// InstanceInfo represents a running Waypoint instance discovered from Redis.
type InstanceInfo struct {
	ID           string
	Hostname     string
	StartedAt    time.Time
	HeartbeatAt  time.Time
	Listeners    string // JSON string
	ActiveConns  int64
	TotalConns   int64
	BytesRead    int64
	BytesWritten int64
}

// HealthStatus returns the health indicator based on heartbeat age.
func (i InstanceInfo) HealthStatus() string {
	age := time.Since(i.HeartbeatAt)
	switch {
	case age < 15*time.Second:
		return "healthy"
	case age < 25*time.Second:
		return "warning"
	default:
		return "critical"
	}
}

// Uptime returns the duration since the instance started.
func (i InstanceInfo) Uptime() time.Duration {
	return time.Since(i.StartedAt).Truncate(time.Second)
}

// UserStats holds per-user limit statistics from Redis.
type UserStats struct {
	LoginName   string
	ActiveConns int64
	TotalBytes  int64
	Bandwidth   []BandwidthStat
}

// BandwidthStat represents bandwidth usage for a single period.
type BandwidthStat struct {
	Period    time.Duration
	PeriodStr string
	Bytes     int64
}
