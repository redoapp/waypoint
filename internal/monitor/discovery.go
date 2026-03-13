package monitor

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store provides access to Redis for the monitor.
type Store struct {
	client    *redis.Client
	keyPrefix string
}

// NewStore creates a new monitor store.
func NewStore(client *redis.Client, keyPrefix string) *Store {
	if keyPrefix == "" {
		keyPrefix = "waypoint:"
	}
	return &Store{client: client, keyPrefix: keyPrefix}
}

// DiscoverInstances scans for all instance heartbeat keys and returns their info.
func (s *Store) DiscoverInstances(ctx context.Context) ([]InstanceInfo, error) {
	pattern := s.keyPrefix + "instance:*"
	var instances []InstanceInfo

	iter := s.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		// Extract instance ID from key.
		id := key[len(s.keyPrefix+"instance:"):]

		fields, err := s.client.HGetAll(ctx, key).Result()
		if err != nil || len(fields) == 0 {
			continue
		}

		info := InstanceInfo{
			ID:           id,
			Hostname:     fields["hostname"],
			Listeners:    fields["listeners"],
			ActiveConns:  parseInt64(fields["active_conns"]),
			TotalConns:   parseInt64(fields["total_conns"]),
			BytesRead:    parseInt64(fields["bytes_read"]),
			BytesWritten: parseInt64(fields["bytes_written"]),
		}

		if t, err := time.Parse(time.RFC3339, fields["started_at"]); err == nil {
			info.StartedAt = t
		}
		if t, err := time.Parse(time.RFC3339, fields["heartbeat_at"]); err == nil {
			info.HeartbeatAt = t
		}

		instances = append(instances, info)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return instances, nil
}

func parseInt64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
