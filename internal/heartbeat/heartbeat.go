package heartbeat

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/config"
)

// Stats holds runtime statistics for an instance.
type Stats struct {
	ActiveConns  int64
	TotalConns   int64
	BytesRead    int64
	BytesWritten int64
}

// Config configures the heartbeat publisher.
type Config struct {
	InstanceID string
	Client     *redis.Client
	KeyPrefix  string
	Hostname   string
	Listeners  []config.ListenerConfig
	StatsFunc  func() Stats
	Logger     *slog.Logger
}

// Run publishes a heartbeat to Redis every 10 seconds.
// It deletes the instance key on context cancellation (clean shutdown).
func Run(ctx context.Context, cfg Config) {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "waypoint:"
	}
	key := prefix + "instance:" + cfg.InstanceID

	// Publish only a redacted view of the listeners. The heartbeat is stored in
	// Redis (readable by anyone with Redis access) and rendered by the monitor UI,
	// so admin DB credentials must never appear here. Using a dedicated allowlist
	// struct — rather than marshaling config.ListenerConfig — keeps new secret
	// fields out of the heartbeat by default.
	listenersJSON, err := json.Marshal(redactListeners(cfg.Listeners))
	if err != nil {
		cfg.Logger.Error("failed to marshal listeners", "error", err)
		listenersJSON = []byte("[]")
	}

	startedAt := time.Now().UTC().Format(time.RFC3339)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	publish := func() {
		stats := cfg.StatsFunc()
		fields := map[string]interface{}{
			"hostname":      cfg.Hostname,
			"started_at":    startedAt,
			"heartbeat_at":  time.Now().UTC().Format(time.RFC3339),
			"listeners":     string(listenersJSON),
			"active_conns":  stats.ActiveConns,
			"total_conns":   stats.TotalConns,
			"bytes_read":    stats.BytesRead,
			"bytes_written": stats.BytesWritten,
		}

		pipe := cfg.Client.Pipeline()
		pipe.HSet(ctx, key, fields)
		pipe.Expire(ctx, key, 30*time.Second)
		if _, err := pipe.Exec(ctx); err != nil {
			cfg.Logger.Error("heartbeat publish failed", "error", err)
		}
	}

	// Publish immediately on start.
	publish()

	for {
		select {
		case <-ctx.Done():
			// Clean shutdown: delete instance key.
			delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := cfg.Client.Del(delCtx, key).Err(); err != nil {
				cfg.Logger.Error("failed to delete heartbeat key", "error", err)
			}
			cancel()
			return
		case <-ticker.C:
			publish()
		}
	}
}

// RedactedListener is the subset of config.ListenerConfig that is safe to
// publish in the heartbeat. It deliberately omits all admin credential blocks
// (Postgres/MongoDB admin passwords, static-user passwords); only the
// provisioner kind is surfaced.
type RedactedListener struct {
	Name        string `json:"name"`
	Listen      string `json:"listen"`
	Mode        string `json:"mode"`
	Backend     string `json:"backend"`
	Advertise   string `json:"advertise,omitempty"`
	BackendTLS  bool   `json:"tls"`
	Provisioner string `json:"provisioner,omitempty"` // "postgres" | "mongodb" | ""
}

// redactListeners maps full listener configs to their credential-free view.
func redactListeners(listeners []config.ListenerConfig) []RedactedListener {
	out := make([]RedactedListener, 0, len(listeners))
	for _, l := range listeners {
		rl := RedactedListener{
			Name:       l.Name,
			Listen:     l.Listen,
			Mode:       l.Mode,
			Backend:    l.Backend,
			Advertise:  l.Advertise,
			BackendTLS: l.BackendTLS,
		}
		switch {
		case l.Postgres != nil:
			rl.Provisioner = "postgres"
		case l.MongoDB != nil:
			rl.Provisioner = "mongodb"
		}
		out = append(out, rl)
	}
	return out
}

// Key returns the Redis key for a given instance ID.
func Key(keyPrefix, instanceID string) string {
	if keyPrefix == "" {
		keyPrefix = "waypoint:"
	}
	return fmt.Sprintf("%sinstance:%s", keyPrefix, instanceID)
}
