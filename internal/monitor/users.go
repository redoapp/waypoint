package monitor

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// ListUsers discovers all users that have keys in Redis and returns their stats.
func (s *Store) ListUsers(ctx context.Context) ([]UserStats, error) {
	users := make(map[string]*UserStats)

	// Scan for connection keys: {prefix}conns:{user}
	if err := s.scanKeys(ctx, s.keyPrefix+"conns:*", func(key string) error {
		user := key[len(s.keyPrefix+"conns:"):]
		val, err := s.client.Get(ctx, key).Int64()
		if err != nil && err != redis.Nil {
			return err
		}
		s.ensureUser(users, user).ActiveConns = val
		return nil
	}); err != nil {
		return nil, fmt.Errorf("scan conns: %w", err)
	}

	// Scan for byte keys: {prefix}bytes:{user}
	if err := s.scanKeys(ctx, s.keyPrefix+"bytes:*", func(key string) error {
		user := key[len(s.keyPrefix+"bytes:"):]
		val, err := s.client.Get(ctx, key).Int64()
		if err != nil && err != redis.Nil {
			return err
		}
		s.ensureUser(users, user).TotalBytes = val
		return nil
	}); err != nil {
		return nil, fmt.Errorf("scan bytes: %w", err)
	}

	// Scan for bandwidth keys: {prefix}bw:{user}:{periodSecs}
	if err := s.scanKeys(ctx, s.keyPrefix+"bw:*", func(key string) error {
		// Parse: {prefix}bw:{user}:{periodSecs}
		rest := key[len(s.keyPrefix+"bw:"):]
		lastColon := strings.LastIndex(rest, ":")
		if lastColon < 0 {
			return nil
		}
		user := rest[:lastColon]
		periodStr := rest[lastColon+1:]
		periodSecs, err := strconv.ParseInt(periodStr, 10, 64)
		if err != nil {
			return nil
		}

		// Read total from the hash using sliding window read.
		total, err := s.readBandwidth(ctx, key, time.Duration(periodSecs)*time.Second)
		if err != nil {
			return nil
		}

		u := s.ensureUser(users, user)
		u.Bandwidth = append(u.Bandwidth, BandwidthStat{
			Period:    time.Duration(periodSecs) * time.Second,
			PeriodStr: formatDuration(time.Duration(periodSecs) * time.Second),
			Bytes:     total,
		})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("scan bandwidth: %w", err)
	}

	result := make([]UserStats, 0, len(users))
	for _, u := range users {
		sort.Slice(u.Bandwidth, func(i, j int) bool {
			return u.Bandwidth[i].Period < u.Bandwidth[j].Period
		})
		result = append(result, *u)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].LoginName < result[j].LoginName
	})
	return result, nil
}

// GetUserStats returns stats for a single user.
func (s *Store) GetUserStats(ctx context.Context, user string) (*UserStats, error) {
	stats := &UserStats{LoginName: user}

	// Connections.
	val, err := s.client.Get(ctx, s.keyPrefix+"conns:"+user).Int64()
	if err != nil && err != redis.Nil {
		return nil, err
	}
	stats.ActiveConns = val

	// Bytes.
	val, err = s.client.Get(ctx, s.keyPrefix+"bytes:"+user).Int64()
	if err != nil && err != redis.Nil {
		return nil, err
	}
	stats.TotalBytes = val

	// Bandwidth: scan for all periods.
	if err := s.scanKeys(ctx, s.keyPrefix+"bw:"+user+":*", func(key string) error {
		rest := key[len(s.keyPrefix+"bw:"+user+":"):]
		periodSecs, err := strconv.ParseInt(rest, 10, 64)
		if err != nil {
			return nil
		}
		total, err := s.readBandwidth(ctx, key, time.Duration(periodSecs)*time.Second)
		if err != nil {
			return nil
		}
		stats.Bandwidth = append(stats.Bandwidth, BandwidthStat{
			Period:    time.Duration(periodSecs) * time.Second,
			PeriodStr: formatDuration(time.Duration(periodSecs) * time.Second),
			Bytes:     total,
		})
		return nil
	}); err != nil {
		return nil, err
	}

	sort.Slice(stats.Bandwidth, func(i, j int) bool {
		return stats.Bandwidth[i].Period < stats.Bandwidth[j].Period
	})
	return stats, nil
}

// ResetConns resets the connection count for a user.
func (s *Store) ResetConns(ctx context.Context, user string) error {
	return s.client.Del(ctx, s.keyPrefix+"conns:"+user).Err()
}

// ResetBytes resets the total byte count for a user.
func (s *Store) ResetBytes(ctx context.Context, user string) error {
	return s.client.Del(ctx, s.keyPrefix+"bytes:"+user).Err()
}

// ResetBandwidth resets bandwidth for a specific period.
func (s *Store) ResetBandwidth(ctx context.Context, user string, periodSecs int64) error {
	key := fmt.Sprintf("%sbw:%s:%d", s.keyPrefix, user, periodSecs)
	return s.client.Del(ctx, key).Err()
}

// ResetAll resets all limits for a user.
func (s *Store) ResetAll(ctx context.Context, user string) error {
	// Delete conns and bytes keys directly.
	s.client.Del(ctx, s.keyPrefix+"conns:"+user)
	s.client.Del(ctx, s.keyPrefix+"bytes:"+user)

	// Scan and delete all bandwidth keys.
	return s.scanKeys(ctx, s.keyPrefix+"bw:"+user+":*", func(key string) error {
		return s.client.Del(ctx, key).Err()
	})
}

func (s *Store) ensureUser(users map[string]*UserStats, name string) *UserStats {
	if u, ok := users[name]; ok {
		return u
	}
	u := &UserStats{LoginName: name}
	users[name] = u
	return u
}

func (s *Store) scanKeys(ctx context.Context, pattern string, fn func(string) error) error {
	iter := s.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		if err := fn(iter.Val()); err != nil {
			return err
		}
	}
	return iter.Err()
}

// slidingWindowReadScript sums valid sub-buckets without modifying data.
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

func (s *Store) readBandwidth(ctx context.Context, key string, period time.Duration) (int64, error) {
	periodSecs := int64(period.Seconds())
	bSize := periodSecs / 360
	if bSize < 10 {
		bSize = 10
	}
	now := time.Now().Unix()
	currentBucket := now / bSize
	minBucket := currentBucket - (periodSecs / bSize)

	val, err := slidingWindowReadScript.Run(ctx, s.client, []string{key}, minBucket).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func formatDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	case d >= time.Hour:
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	case d >= time.Minute:
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	default:
		secs := int(d.Seconds())
		return fmt.Sprintf("%d seconds", secs)
	}
}
