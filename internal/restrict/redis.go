package restrict

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
)

// RedisStore manages per-user counters in Redis.
type RedisStore struct {
	client    *redis.Client
	keyPrefix string
	metrics   *metrics.Metrics
	// nowFunc allows tests to override time.Now for sliding window calculations.
	nowFunc func() time.Time
}

// NewRedisStore creates a new Redis-backed counter store.
func NewRedisStore(client *redis.Client, keyPrefix string, m *metrics.Metrics) *RedisStore {
	if keyPrefix == "" {
		keyPrefix = "waypoint:"
	}
	return &RedisStore{client: client, keyPrefix: keyPrefix, metrics: m, nowFunc: time.Now}
}

func (s *RedisStore) recordOp(ctx context.Context, op string, start time.Time, err error) {
	duration := time.Since(start).Seconds()
	attrs := s.metrics.Attrs("waypoint.redis.op_duration", metrics.AttrOperation.String(op))
	s.metrics.RedisOpDuration.Record(ctx, duration, attrs)
	if err != nil {
		errAttrs := s.metrics.Attrs("waypoint.redis.errors", metrics.AttrOperation.String(op))
		s.metrics.RedisErrors.Add(ctx, 1, errAttrs)
	}
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
	start := time.Now()
	val, err := s.client.Incr(ctx, s.key("conns", user)).Result()
	s.recordOp(ctx, "incr_conns", start, err)
	return val, err
}

// DecrConns decrements the connection count for a user.
func (s *RedisStore) DecrConns(ctx context.Context, user string) error {
	start := time.Now()
	k := s.key("conns", user)
	val, err := s.client.Decr(ctx, k).Result()
	s.recordOp(ctx, "decr_conns", start, err)
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
	start := time.Now()
	val, err := s.client.Get(ctx, s.key("conns", user)).Int64()
	if err == redis.Nil {
		s.recordOp(ctx, "get_conns", start, nil)
		return 0, nil
	}
	s.recordOp(ctx, "get_conns", start, err)
	return val, err
}

// AddBytes adds to the total byte count for a user. Used for per-user aggregate tracking.
func (s *RedisStore) AddBytes(ctx context.Context, user string, n int64) (int64, error) {
	start := time.Now()
	val, err := s.client.IncrBy(ctx, s.key("bytes", user), n).Result()
	s.recordOp(ctx, "add_bytes", start, err)
	return val, err
}

// bucketSize returns the sub-bucket duration in seconds for a given period.
// Targets ~360 sub-buckets per period, with a minimum of 10 seconds.
func bucketSize(period time.Duration) int64 {
	size := int64(period.Seconds()) / 360
	if size < 10 {
		size = 10
	}
	return size
}

// slidingWindowScript is a Lua script that implements a sliding window counter
// using Redis Hashes with sub-buckets. It:
//  1. Adds bytes to the current sub-bucket via HINCRBY
//  2. Sums all valid (non-expired) sub-buckets
//  3. Cleans up expired sub-bucket fields
//  4. Sets the key TTL
//
// KEYS[1] = hash key
// ARGV[1] = bytes to add
// ARGV[2] = current sub-bucket ID (string)
// ARGV[3] = minimum valid sub-bucket ID (numeric threshold)
// ARGV[4] = key TTL in seconds
//
// Returns: total bytes across all valid sub-buckets (including the newly added)
var slidingWindowScript = redis.NewScript(`
local bytes_to_add = tonumber(ARGV[1])
local sub_bucket = ARGV[2]
local min_bucket = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

-- Add bytes to current sub-bucket.
redis.call('HINCRBY', KEYS[1], sub_bucket, bytes_to_add)
redis.call('EXPIRE', KEYS[1], ttl)

-- Sum valid buckets and collect expired ones.
local all = redis.call('HGETALL', KEYS[1])
local total = 0
local expired = {}
for i = 1, #all, 2 do
    local bucket_id = tonumber(all[i])
    if bucket_id >= min_bucket then
        total = total + tonumber(all[i + 1])
    else
        expired[#expired + 1] = all[i]
    end
end

-- Clean up expired fields.
if #expired > 0 then
    redis.call('HDEL', KEYS[1], unpack(expired))
end

return total
`)

// slidingWindowReadScript is a read-only variant that sums valid sub-buckets
// without modifying any data.
//
// KEYS[1] = hash key
// ARGV[1] = minimum valid sub-bucket ID
var slidingWindowReadScript = redis.NewScript(`
local min_bucket = tonumber(ARGV[1])
local all = redis.call('HGETALL', KEYS[1])
local total = 0
for i = 1, #all, 2 do
    if tonumber(all[i]) >= min_bucket then
        total = total + tonumber(all[i + 1])
    end
end
return total
`)

// BandwidthResult holds the result of a multi-tier bandwidth check.
type BandwidthResult struct {
	// Exceeded is true if any tier's limit was exceeded.
	Exceeded bool
	// ExceededTier is the index of the first exceeded tier, or -1 if none.
	ExceededTier int
}

// AddBandwidthBytesMulti adds bytes to all bandwidth tiers using the sliding window.
// It iterates per-tier (not atomic across tiers). Returns which tier was exceeded, if any.
func (s *RedisStore) AddBandwidthBytesMulti(ctx context.Context, user string, n int64, tiers []auth.BandwidthTier) (BandwidthResult, error) {
	start := time.Now()
	now := s.nowFunc().Unix()

	for i, tier := range tiers {
		bSize := bucketSize(tier.Period)
		currentBucket := now / bSize
		periodSecs := int64(tier.Period.Seconds())
		minBucket := currentBucket - (periodSecs / bSize)
		ttl := periodSecs + bSize // TTL = period + one bucket for safety

		hashKey := s.key("bw", user, fmt.Sprintf("%d", periodSecs))

		total, err := slidingWindowScript.Run(ctx, s.client, []string{hashKey},
			n,
			fmt.Sprintf("%d", currentBucket),
			minBucket,
			ttl,
		).Int64()
		if err != nil {
			s.recordOp(ctx, "add_bandwidth", start, err)
			return BandwidthResult{}, fmt.Errorf("sliding window tier %d: %w", i, err)
		}

		if total > tier.Bytes {
			s.recordOp(ctx, "add_bandwidth", start, nil)
			return BandwidthResult{Exceeded: true, ExceededTier: i}, nil
		}
	}

	s.recordOp(ctx, "add_bandwidth", start, nil)
	return BandwidthResult{ExceededTier: -1}, nil
}

// GetBandwidthBytes returns the current bandwidth usage for a single period
// using the sliding window (read-only).
func (s *RedisStore) GetBandwidthBytes(ctx context.Context, user string, period time.Duration) (int64, error) {
	start := time.Now()
	now := s.nowFunc().Unix()
	bSize := bucketSize(period)
	periodSecs := int64(period.Seconds())
	currentBucket := now / bSize
	minBucket := currentBucket - (periodSecs / bSize)

	hashKey := s.key("bw", user, fmt.Sprintf("%d", periodSecs))

	val, err := slidingWindowReadScript.Run(ctx, s.client, []string{hashKey}, minBucket).Int64()
	if err == redis.Nil {
		s.recordOp(ctx, "get_bandwidth", start, nil)
		return 0, nil
	}
	s.recordOp(ctx, "get_bandwidth", start, err)
	return val, err
}

// TouchLastUsed updates the last-used timestamp for a provisioned user.
func (s *RedisStore) TouchLastUsed(ctx context.Context, pgUser string) error {
	start := time.Now()
	err := s.client.Set(ctx, s.key("lastused", pgUser), time.Now().Unix(), 0).Err()
	s.recordOp(ctx, "touch_last_used", start, err)
	return err
}

// GetLastUsed returns the last-used time for a provisioned user.
func (s *RedisStore) GetLastUsed(ctx context.Context, pgUser string) (time.Time, error) {
	start := time.Now()
	val, err := s.client.Get(ctx, s.key("lastused", pgUser)).Int64()
	if err == redis.Nil {
		s.recordOp(ctx, "get_last_used", start, nil)
		return time.Time{}, nil
	}
	if err != nil {
		s.recordOp(ctx, "get_last_used", start, err)
		return time.Time{}, err
	}
	s.recordOp(ctx, "get_last_used", start, nil)
	return time.Unix(val, 0), nil
}
