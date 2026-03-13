package restrict

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore manages per-user counters in Redis.
type RedisStore struct {
	client    *redis.Client
	keyPrefix string
}

// NewRedisStore creates a new Redis-backed counter store.
func NewRedisStore(client *redis.Client, keyPrefix string) *RedisStore {
	if keyPrefix == "" {
		keyPrefix = "waypoint:"
	}
	return &RedisStore{client: client, keyPrefix: keyPrefix}
}

func (s *RedisStore) key(parts ...string) string {
	k := s.keyPrefix
	for _, p := range parts {
		k += p + ":"
	}
	return k[:len(k)-1] // trim trailing colon
}

// IncrConns atomically increments the connection count for a user.
// Returns the new count.
func (s *RedisStore) IncrConns(ctx context.Context, user string) (int64, error) {
	return s.client.Incr(ctx, s.key("conns", user)).Result()
}

// DecrConns decrements the connection count for a user.
func (s *RedisStore) DecrConns(ctx context.Context, user string) error {
	k := s.key("conns", user)
	val, err := s.client.Decr(ctx, k).Result()
	if err != nil {
		return err
	}
	// Clean up if zero or negative.
	if val <= 0 {
		s.client.Del(ctx, k)
	}
	return nil
}

// GetConns returns the current connection count for a user.
func (s *RedisStore) GetConns(ctx context.Context, user string) (int64, error) {
	val, err := s.client.Get(ctx, s.key("conns", user)).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

// AddBytes adds to the total byte count for a user. Used for per-user aggregate tracking.
func (s *RedisStore) AddBytes(ctx context.Context, user string, n int64) (int64, error) {
	return s.client.IncrBy(ctx, s.key("bytes", user), n).Result()
}

// AddBandwidthBytes adds bytes to the bandwidth counter for the current period.
// The key expires after the period duration.
func (s *RedisStore) AddBandwidthBytes(ctx context.Context, user string, n int64, period time.Duration) (int64, error) {
	k := s.key("bw", user, periodBucket(period))
	pipe := s.client.Pipeline()
	incr := pipe.IncrBy(ctx, k, n)
	// Set expiry only if the key is new (NX). Approximate: we always set it,
	// but Redis EXPIRE on an existing key just resets TTL — acceptable for our needs.
	pipe.Expire(ctx, k, period)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

// GetBandwidthBytes returns the current bandwidth usage for the period.
func (s *RedisStore) GetBandwidthBytes(ctx context.Context, user string, period time.Duration) (int64, error) {
	val, err := s.client.Get(ctx, s.key("bw", user, periodBucket(period))).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

// TouchLastUsed updates the last-used timestamp for a provisioned user.
func (s *RedisStore) TouchLastUsed(ctx context.Context, pgUser string) error {
	return s.client.Set(ctx, s.key("lastused", pgUser), time.Now().Unix(), 0).Err()
}

// GetLastUsed returns the last-used time for a provisioned user.
func (s *RedisStore) GetLastUsed(ctx context.Context, pgUser string) (time.Time, error) {
	val, err := s.client.Get(ctx, s.key("lastused", pgUser)).Int64()
	if err == redis.Nil {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(val, 0), nil
}

// periodBucket returns a key suffix that identifies the current time bucket
// for a given period duration.
func periodBucket(period time.Duration) string {
	bucket := time.Now().Unix() / int64(period.Seconds())
	return fmt.Sprintf("%d_%d", int64(period.Seconds()), bucket)
}
