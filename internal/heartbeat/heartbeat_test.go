package heartbeat

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/config"
)

func TestKey(t *testing.T) {
	tests := []struct {
		prefix string
		id     string
		want   string
	}{
		{"", "abc-123", "waypoint:instance:abc-123"},
		{"wp:", "abc-123", "wp:instance:abc-123"},
		{"custom:", "node-1", "custom:instance:node-1"},
	}
	for _, tt := range tests {
		got := Key(tt.prefix, tt.id)
		if got != tt.want {
			t.Errorf("Key(%q, %q) = %q, want %q", tt.prefix, tt.id, got, tt.want)
		}
	}
}

func TestHeartbeat(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	ctx, cancel := context.WithCancel(context.Background())

	listeners := []config.ListenerConfig{
		{Name: "test-tcp", Listen: ":5432", Mode: "tcp", Backend: "db:5432"},
	}

	cfg := Config{
		InstanceID: "test-instance-123",
		Client:     rdb,
		KeyPrefix:  "wp:",
		Hostname:   "test-host",
		Listeners:  listeners,
		StatsFunc: func() Stats {
			return Stats{ActiveConns: 5, TotalConns: 100, BytesRead: 1024, BytesWritten: 2048}
		},
		Logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}

	done := make(chan struct{})
	go func() {
		Run(ctx, cfg)
		close(done)
	}()

	// Wait for initial publish.
	time.Sleep(100 * time.Millisecond)

	key := "wp:instance:test-instance-123"
	fields, err := rdb.HGetAll(context.Background(), key).Result()
	if err != nil {
		t.Fatal(err)
	}

	if fields["hostname"] != "test-host" {
		t.Errorf("hostname = %q, want %q", fields["hostname"], "test-host")
	}
	if fields["active_conns"] != "5" {
		t.Errorf("active_conns = %q, want %q", fields["active_conns"], "5")
	}
	if fields["total_conns"] != "100" {
		t.Errorf("total_conns = %q, want %q", fields["total_conns"], "100")
	}
	if fields["bytes_read"] != "1024" {
		t.Errorf("bytes_read = %q, want %q", fields["bytes_read"], "1024")
	}
	if fields["bytes_written"] != "2048" {
		t.Errorf("bytes_written = %q, want %q", fields["bytes_written"], "2048")
	}

	// Check listeners JSON.
	var parsedListeners []config.ListenerConfig
	if err := json.Unmarshal([]byte(fields["listeners"]), &parsedListeners); err != nil {
		t.Fatalf("unmarshal listeners: %v", err)
	}
	if len(parsedListeners) != 1 || parsedListeners[0].Name != "test-tcp" {
		t.Errorf("unexpected listeners: %+v", parsedListeners)
	}

	// Check TTL is set.
	ttl := mr.TTL(key)
	if ttl <= 0 || ttl > 30*time.Second {
		t.Errorf("TTL = %v, want >0 and <=30s", ttl)
	}

	// Cancel and check cleanup.
	cancel()
	<-done

	exists := mr.Exists(key)
	if exists {
		t.Error("heartbeat key should be deleted after shutdown")
	}
}
