package restrict

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
)

// RedisStore manages per-user counters in Redis.
type RedisStore struct {
	client    redis.UniversalClient
	keyPrefix string
	metrics   *metrics.Metrics
	// nowFunc allows tests to override time.Now for sliding window calculations.
	nowFunc func() time.Time
}

// NewRedisStore creates a new Redis-backed counter store.
func NewRedisStore(client redis.UniversalClient, keyPrefix string, m *metrics.Metrics) *RedisStore {
	if keyPrefix == "" {
		keyPrefix = "waypoint:"
	}
	return &RedisStore{client: client, keyPrefix: keyPrefix, metrics: m, nowFunc: time.Now}
}

func (s *RedisStore) startOp(ctx context.Context, op string) (context.Context, trace.Span) {
	return s.metrics.Tracer().Start(ctx, "waypoint.redis."+op,
		trace.WithAttributes(attribute.String("waypoint.operation", op)),
	)
}

func (s *RedisStore) recordOp(ctx context.Context, span trace.Span, op string, start time.Time, err error) {
	duration := time.Since(start).Seconds()
	attrs := s.metrics.Attrs("waypoint.redis.op_duration", metrics.AttrOperation.String(op))
	s.metrics.RedisOpDuration.Record(ctx, duration, attrs)
	if err != nil {
		errAttrs := s.metrics.Attrs("waypoint.redis.errors", metrics.AttrOperation.String(op))
		s.metrics.RedisErrors.Add(ctx, 1, errAttrs)
		span.RecordError(err)
		span.SetStatus(codes.Error, "redis error")
	}
	span.End()
}

func (s *RedisStore) key(parts ...string) string {
	k := s.keyPrefix
	for _, p := range parts {
		k += p + ":"
	}
	return k[:len(k)-1] // trim trailing colon
}

// ancestorKeys builds Redis keys from leaf to root for hierarchical operations.
// The metric prefix (e.g., "conns") is joined with ":" while path segments
// (user, scope) are joined with "/". The first segment (user) is wrapped in
// Redis hash tags {user} so all keys for the same user map to the same
// cluster hash slot, avoiding CROSSSLOT errors in Lua scripts.
//
// Example: ancestorKeys("conns", "alice", "mongodb")
//
//	→ ["waypoint:conns:{alice}/mongodb", "waypoint:conns:{alice}"]
func (s *RedisStore) ancestorKeys(metric string, segments ...string) []string {
	keys := make([]string, len(segments))
	for i := range segments {
		parts := make([]string, len(segments)-i)
		copy(parts, segments[:len(segments)-i])
		parts[0] = "{" + parts[0] + "}"
		path := strings.Join(parts, "/")
		keys[i] = s.keyPrefix + metric + ":" + path
	}
	return keys
}

// hierarchicalIncrScript atomically increments all ancestor keys.
// KEYS[1..N] = ancestor keys (leaf first, root last)
// ARGV[1]    = value to add
// Returns: leaf value after increment
var hierarchicalIncrScript = redis.NewScript(`
local val = tonumber(ARGV[1])
for i = 1, #KEYS do
    redis.call('INCRBY', KEYS[i], val)
end
return tonumber(redis.call('GET', KEYS[1]))
`)

// hierarchicalDecrScript atomically decrements all ancestor keys.
// Cleans up zero/negative keys.
// KEYS[1..N] = ancestor keys (leaf first, root last)
// ARGV[1]    = value to subtract
var hierarchicalDecrScript = redis.NewScript(`
local val = tonumber(ARGV[1])
for i = 1, #KEYS do
    local n = redis.call('DECRBY', KEYS[i], val)
    if n <= 0 then redis.call('DEL', KEYS[i]) end
end
`)

type connAcquireDecision int64

const (
	connAcquireOK connAcquireDecision = iota
	connAcquireEndpointLimit
	connAcquireGlobalLimit
)

// limitedAcquireConnsScript checks connection limits and increments counters
// in a single Redis operation. This avoids a high-contention race where all
// contenders increment, observe an exceeded global count, and then all fail.
//
// KEYS[1..N] = ancestor keys (leaf first, root last)
// ARGV[1]    = endpoint max connections, or 0 for no limit
// ARGV[2]    = global max connections, or 0 for no limit
// Returns: {decision, leaf count, root count}
var limitedAcquireConnsScript = redis.NewScript(`
local endpoint_max = tonumber(ARGV[1])
local global_max = tonumber(ARGV[2])
local leaf = tonumber(redis.call('GET', KEYS[1]) or '0')
local root = tonumber(redis.call('GET', KEYS[#KEYS]) or '0')

if endpoint_max > 0 and leaf >= endpoint_max then
    return {1, leaf, root}
end

if global_max > 0 and root >= global_max then
    return {2, leaf, root}
end

for i = 1, #KEYS do
    redis.call('INCRBY', KEYS[i], 1)
end

return {0, leaf + 1, root + 1}
`)

// hierarchicalSlidingWindowScript runs the sliding window on all ancestor keys.
// KEYS[1..N] = ancestor hash keys (leaf first, root last)
// ARGV[1]    = bytes to add
// ARGV[2]    = current sub-bucket ID
// ARGV[3]    = minimum valid sub-bucket ID
// ARGV[4]    = key TTL in seconds
// Returns: leaf total (for enforcement)
var hierarchicalSlidingWindowScript = redis.NewScript(`
local bytes_to_add = tonumber(ARGV[1])
local sub_bucket = ARGV[2]
local min_bucket = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local leaf_total = 0

for i = 1, #KEYS do
    redis.call('HINCRBY', KEYS[i], sub_bucket, bytes_to_add)
    redis.call('EXPIRE', KEYS[i], ttl)

    local all = redis.call('HGETALL', KEYS[i])
    local total = 0
    local expired = {}
    for j = 1, #all, 2 do
        local bucket_id = tonumber(all[j])
        if bucket_id >= min_bucket then
            total = total + tonumber(all[j + 1])
        else
            expired[#expired + 1] = all[j]
        end
    end
    if #expired > 0 then
        redis.call('HDEL', KEYS[i], unpack(expired))
    end
    if i == 1 then leaf_total = total end
end

return leaf_total
`)

// hierarchicalAddScript atomically adds to byte totals at all ancestor levels.
// KEYS[1..N] = ancestor keys (leaf first, root last)
// ARGV[1]    = bytes to add
// Returns: leaf value
var hierarchicalAddScript = redis.NewScript(`
local val = tonumber(ARGV[1])
for i = 1, #KEYS do
    redis.call('INCRBY', KEYS[i], val)
end
return tonumber(redis.call('GET', KEYS[1]))
`)

func (s *RedisStore) connKeys(user, scope string) []string {
	if scope == "" {
		return s.ancestorKeys("conns", user)
	}
	return s.ancestorKeys("conns", user, scope)
}

// IncrConns atomically increments the connection count for a user/scope,
// cascading the increment up to the user-level total.
// Returns the new leaf (scoped) count.
func (s *RedisStore) IncrConns(ctx context.Context, user, scope string) (int64, error) {
	ctx, span := s.startOp(ctx, "incr_conns")
	start := time.Now()
	keys := s.connKeys(user, scope)
	val, err := hierarchicalIncrScript.Run(ctx, s.client, keys, 1).Int64()
	s.recordOp(ctx, span, "incr_conns", start, err)
	return val, err
}

func (s *RedisStore) tryAcquireConns(ctx context.Context, user, scope string, endpointMax, globalMax int) (int64, int64, connAcquireDecision, error) {
	ctx, span := s.startOp(ctx, "try_acquire_conns")
	start := time.Now()
	keys := s.connKeys(user, scope)
	values, err := limitedAcquireConnsScript.Run(ctx, s.client, keys, endpointMax, globalMax).Int64Slice()
	if err == nil && len(values) != 3 {
		err = fmt.Errorf("unexpected acquire result length %d", len(values))
	}
	s.recordOp(ctx, span, "try_acquire_conns", start, err)
	if err != nil {
		return 0, 0, connAcquireOK, err
	}
	return values[1], values[2], connAcquireDecision(values[0]), nil
}

// DecrConns decrements the connection count for a user/scope,
// cascading the decrement up to the user-level total.
func (s *RedisStore) DecrConns(ctx context.Context, user, scope string) error {
	ctx, span := s.startOp(ctx, "decr_conns")
	start := time.Now()
	keys := s.connKeys(user, scope)
	err := hierarchicalDecrScript.Run(ctx, s.client, keys, 1).Err()
	if err == redis.Nil {
		err = nil // script returns nil when keys don't exist
	}
	s.recordOp(ctx, span, "decr_conns", start, err)
	return err
}

// GetConns returns the current connection count at a specific scope level.
// Pass scope="" to read the user-level total, or a listener name for per-endpoint.
func (s *RedisStore) GetConns(ctx context.Context, user, scope string) (int64, error) {
	ctx, span := s.startOp(ctx, "get_conns")
	start := time.Now()
	var k string
	if scope == "" {
		k = s.keyPrefix + "conns:{" + user + "}"
	} else {
		k = s.keyPrefix + "conns:{" + user + "}/" + scope
	}
	val, err := s.client.Get(ctx, k).Int64()
	if err == redis.Nil {
		s.recordOp(ctx, span, "get_conns", start, nil)
		return 0, nil
	}
	s.recordOp(ctx, span, "get_conns", start, err)
	return val, err
}

// AddBytes adds to the total byte count, cascading up from scope to user total.
func (s *RedisStore) AddBytes(ctx context.Context, user, scope string, n int64) (int64, error) {
	ctx, span := s.startOp(ctx, "add_bytes")
	start := time.Now()
	keys := s.ancestorKeys("bytes", user, scope)
	val, err := hierarchicalAddScript.Run(ctx, s.client, keys, n).Int64()
	s.recordOp(ctx, span, "add_bytes", start, err)
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

// AddBandwidthBytesMulti adds bytes to all bandwidth tiers using the hierarchical sliding window.
// Writes cascade from scope (leaf) to user (root) at each tier.
// Returns which tier was exceeded at the leaf level, if any.
func (s *RedisStore) AddBandwidthBytesMulti(ctx context.Context, user, scope string, n int64, tiers []auth.BandwidthTier) (BandwidthResult, error) {
	ctx, span := s.startOp(ctx, "add_bandwidth")
	start := time.Now()
	now := s.nowFunc().Unix()

	for i, tier := range tiers {
		bSize := bucketSize(tier.Period)
		currentBucket := now / bSize
		periodSecs := int64(tier.Period.Seconds())
		minBucket := currentBucket - (periodSecs / bSize)
		ttl := periodSecs + bSize // TTL = period + one bucket for safety

		// Period goes before hierarchy: waypoint:bw:<period>:<user>/<scope>
		keys := s.ancestorKeys(fmt.Sprintf("bw:%d", periodSecs), user, scope)

		total, err := hierarchicalSlidingWindowScript.Run(ctx, s.client, keys,
			n,
			fmt.Sprintf("%d", currentBucket),
			minBucket,
			ttl,
		).Int64()
		if err != nil {
			s.recordOp(ctx, span, "add_bandwidth", start, err)
			return BandwidthResult{}, fmt.Errorf("sliding window tier %d: %w", i, err)
		}

		if total > tier.Bytes {
			s.recordOp(ctx, span, "add_bandwidth", start, nil)
			return BandwidthResult{Exceeded: true, ExceededTier: i}, nil
		}
	}

	s.recordOp(ctx, span, "add_bandwidth", start, nil)
	return BandwidthResult{ExceededTier: -1}, nil
}

// GetBandwidthBytes returns the current bandwidth usage for a single period
// at a specific scope level using the sliding window (read-only).
// Pass scope="" for user-level total, or a listener name for per-endpoint.
func (s *RedisStore) GetBandwidthBytes(ctx context.Context, user, scope string, period time.Duration) (int64, error) {
	ctx, span := s.startOp(ctx, "get_bandwidth")
	start := time.Now()
	now := s.nowFunc().Unix()
	bSize := bucketSize(period)
	periodSecs := int64(period.Seconds())
	currentBucket := now / bSize
	minBucket := currentBucket - (periodSecs / bSize)

	var hashKey string
	if scope == "" {
		hashKey = s.keyPrefix + fmt.Sprintf("bw:%d:", periodSecs) + "{" + user + "}"
	} else {
		hashKey = s.keyPrefix + fmt.Sprintf("bw:%d:", periodSecs) + "{" + user + "}/" + scope
	}

	val, err := slidingWindowReadScript.Run(ctx, s.client, []string{hashKey}, minBucket).Int64()
	if err == redis.Nil {
		s.recordOp(ctx, span, "get_bandwidth", start, nil)
		return 0, nil
	}
	s.recordOp(ctx, span, "get_bandwidth", start, err)
	return val, err
}

// TouchLastUsed updates the last-used timestamp for a provisioned user.
func (s *RedisStore) TouchLastUsed(ctx context.Context, pgUser string) error {
	ctx, span := s.startOp(ctx, "touch_last_used")
	start := time.Now()
	err := s.client.Set(ctx, s.key("lastused", pgUser), time.Now().Unix(), 0).Err()
	s.recordOp(ctx, span, "touch_last_used", start, err)
	return err
}

// GetLastUsed returns the last-used time for a provisioned user.
func (s *RedisStore) GetLastUsed(ctx context.Context, pgUser string) (time.Time, error) {
	ctx, span := s.startOp(ctx, "get_last_used")
	start := time.Now()
	val, err := s.client.Get(ctx, s.key("lastused", pgUser)).Int64()
	if err == redis.Nil {
		s.recordOp(ctx, span, "get_last_used", start, nil)
		return time.Time{}, nil
	}
	if err != nil {
		s.recordOp(ctx, span, "get_last_used", start, err)
		return time.Time{}, err
	}
	s.recordOp(ctx, span, "get_last_used", start, nil)
	return time.Unix(val, 0), nil
}

// releaseLockScript atomically checks the token before deleting the lock key.
var releaseLockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0
`)

// AcquireLock attempts to acquire a distributed lock using Redis SET NX EX.
// Returns a token that must be passed to ReleaseLock, or empty string if not acquired.
func (s *RedisStore) AcquireLock(ctx context.Context, name string, ttl time.Duration) (string, error) {
	ctx, span := s.startOp(ctx, "acquire_lock")
	start := time.Now()
	token := fmt.Sprintf("%d:%d", time.Now().UnixNano(), start.UnixNano())
	key := s.key("lock", name)
	result, err := s.client.SetArgs(ctx, key, token, redis.SetArgs{Mode: "NX", TTL: ttl}).Result()
	if err == redis.Nil {
		s.recordOp(ctx, span, "acquire_lock", start, nil)
		return "", nil
	}
	if err != nil {
		s.recordOp(ctx, span, "acquire_lock", start, err)
		return "", err
	}
	if result != "OK" {
		s.recordOp(ctx, span, "acquire_lock", start, nil)
		return "", nil
	}
	s.recordOp(ctx, span, "acquire_lock", start, nil)
	return token, nil
}

// ReleaseLock releases a distributed lock acquired by AcquireLock.
// The token must match the one returned by AcquireLock.
func (s *RedisStore) ReleaseLock(ctx context.Context, name string, token string) error {
	ctx, span := s.startOp(ctx, "release_lock")
	start := time.Now()
	key := s.key("lock", name)
	err := releaseLockScript.Run(ctx, s.client, []string{key}, token).Err()
	if err == redis.Nil {
		err = nil // lock already expired or released
	}
	s.recordOp(ctx, span, "release_lock", start, err)
	return err
}

// IsGroupReady reports whether a group role has been bootstrapped recently.
// Returns false (without error) when the key is absent so the caller falls
// through to an idempotent re-bootstrap.
func (s *RedisStore) IsGroupReady(ctx context.Context, name string) (bool, error) {
	ctx, span := s.startOp(ctx, "is_group_ready")
	start := time.Now()
	_, err := s.client.Get(ctx, s.key("grp_ready", name)).Result()
	if err == redis.Nil {
		s.recordOp(ctx, span, "is_group_ready", start, nil)
		return false, nil
	}
	if err != nil {
		s.recordOp(ctx, span, "is_group_ready", start, err)
		return false, err
	}
	s.recordOp(ctx, span, "is_group_ready", start, nil)
	return true, nil
}

// MarkGroupReady records that a group role has been bootstrapped. The TTL
// bounds how long the cache is trusted; on miss the bootstrap re-runs
// idempotently.
func (s *RedisStore) MarkGroupReady(ctx context.Context, name string, ttl time.Duration) error {
	ctx, span := s.startOp(ctx, "mark_group_ready")
	start := time.Now()
	err := s.client.Set(ctx, s.key("grp_ready", name), "1", ttl).Err()
	s.recordOp(ctx, span, "mark_group_ready", start, err)
	return err
}
