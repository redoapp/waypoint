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

	listenersJSON, err := json.Marshal(cfg.Listeners)
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

// Key returns the Redis key for a given instance ID.
func Key(keyPrefix, instanceID string) string {
	if keyPrefix == "" {
		keyPrefix = "waypoint:"
	}
	return fmt.Sprintf("%sinstance:%s", keyPrefix, instanceID)
}
