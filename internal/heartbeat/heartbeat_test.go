package heartbeat

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
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

	const adminSecret = "SUPER_SECRET_ADMIN_PW"
	const staticSecret = "STATIC_USER_SECRET"
	listeners := []config.ListenerConfig{
		{Name: "test-tcp", Listen: ":5432", Mode: "tcp", Backend: "db:5432"},
		{
			Name: "test-pg", Listen: ":5433", Mode: "postgres", Backend: "pg:5432",
			Postgres: &config.PostgresAdmin{AdminUser: "admin", AdminPassword: adminSecret},
		},
		{
			Name: "test-mongo", Listen: ":27017", Mode: "mongodb", Backend: "mongo:27017",
			MongoDB: &config.MongoDBAdmin{
				AdminUser: "admin", AdminPassword: adminSecret,
				Provision: &config.MongoProvision{
					Mode:        config.MongoProvisionStatic,
					StaticUsers: []config.MongoStaticUser{{Name: "ro", Username: "ro", Password: staticSecret}},
				},
			},
		},
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

	// Admin credentials must never be published to Redis.
	if strings.Contains(fields["listeners"], adminSecret) || strings.Contains(fields["listeners"], staticSecret) {
		t.Fatalf("heartbeat leaked a secret into Redis: %s", fields["listeners"])
	}

	// Check redacted listeners JSON: names preserved, provisioner kind surfaced.
	var parsedListeners []RedactedListener
	if err := json.Unmarshal([]byte(fields["listeners"]), &parsedListeners); err != nil {
		t.Fatalf("unmarshal listeners: %v", err)
	}
	if len(parsedListeners) != 3 {
		t.Fatalf("got %d listeners, want 3: %+v", len(parsedListeners), parsedListeners)
	}
	byName := map[string]RedactedListener{}
	for _, l := range parsedListeners {
		byName[l.Name] = l
	}
	if byName["test-tcp"].Provisioner != "" {
		t.Errorf("test-tcp provisioner = %q, want empty", byName["test-tcp"].Provisioner)
	}
	if byName["test-pg"].Provisioner != "postgres" {
		t.Errorf("test-pg provisioner = %q, want postgres", byName["test-pg"].Provisioner)
	}
	if byName["test-mongo"].Provisioner != "mongodb" {
		t.Errorf("test-mongo provisioner = %q, want mongodb", byName["test-mongo"].Provisioner)
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
