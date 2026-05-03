package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "waypoint.toml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

const validMinimalConfig = `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "test-tcp"
listen = ":9999"
mode = "tcp"
backend = "10.0.0.1:5432"
`

func TestLoad_ValidMinimal(t *testing.T) {
	path := writeTestConfig(t, validMinimalConfig)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tailscale.Hostname != "waypoint-test" {
		t.Errorf("hostname = %q, want waypoint-test", cfg.Tailscale.Hostname)
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].Name != "test-tcp" {
		t.Errorf("listener name = %q, want test-tcp", cfg.Listeners[0].Name)
	}
}

func TestLoad_FullConfig(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-db"
state_dir = "/tmp/tsnet"

[redis]
address = "redis:6379"
password = "secret"
db = 1
key_prefix = "wp:"

[revalidation]
interval = "30s"

[defaults.limits]
max_conns_total = 100

[[listeners]]
name = "pg-main"
listen = ":5432"
mode = "postgres"
backend = "10.0.1.10:5432"

[listeners.postgres]
admin_user = "admin"
admin_password = "pass"
admin_database = "postgres"
user_prefix = "wp_"
user_ttl = "12h"

[[listeners]]
name = "raw-mysql"
listen = ":3306"
mode = "tcp"
backend = "10.0.1.5:3306"
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Redis.Address != "redis:6379" {
		t.Errorf("redis address = %q", cfg.Redis.Address)
	}
	if cfg.Redis.Password != "secret" {
		t.Errorf("redis password = %q", cfg.Redis.Password)
	}
	if cfg.Redis.DB != 1 {
		t.Errorf("redis db = %d", cfg.Redis.DB)
	}
	if cfg.Redis.KeyPrefix != "wp:" {
		t.Errorf("redis key_prefix = %q", cfg.Redis.KeyPrefix)
	}
	if cfg.Revalidation.IntervalDuration() != 30*time.Second {
		t.Errorf("revalidation interval = %v", cfg.Revalidation.IntervalDuration())
	}
	if cfg.Defaults.Limits.MaxConnsTotal != 100 {
		t.Errorf("max_conns_total = %d", cfg.Defaults.Limits.MaxConnsTotal)
	}
	if len(cfg.Listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(cfg.Listeners))
	}

	pg := cfg.Listeners[0]
	if pg.Postgres == nil {
		t.Fatal("expected postgres config")
	}
	if pg.Postgres.AdminUser != "admin" {
		t.Errorf("admin_user = %q", pg.Postgres.AdminUser)
	}
	if pg.Postgres.UserTTLDuration() != 12*time.Hour {
		t.Errorf("user_ttl = %v", pg.Postgres.UserTTLDuration())
	}
}

func TestLoad_EnvVarExpansion(t *testing.T) {
	t.Setenv("TEST_PG_PASS", "mysecretpass")

	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "pg"
listen = ":5432"
mode = "postgres"
backend = "localhost:5432"

[listeners.postgres]
admin_user = "admin"
admin_password = "${TEST_PG_PASS}"
admin_database = "postgres"
user_prefix = "wp_"
user_ttl = "24h"
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listeners[0].Postgres.AdminPassword != "mysecretpass" {
		t.Errorf("expected env var expansion, got %q", cfg.Listeners[0].Postgres.AdminPassword)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	path := writeTestConfig(t, `[tailscale
hostname = "test"`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestValidate_MissingHostname(t *testing.T) {
	content := `
[tailscale]

[[listeners]]
name = "test"
listen = ":9999"
mode = "tcp"
backend = "10.0.0.1:5432"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "hostname") {
		t.Errorf("expected hostname error, got: %v", err)
	}
}

func TestValidate_NoListeners(t *testing.T) {
	content := `
[tailscale]
hostname = "test"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "listeners") {
		t.Errorf("expected listeners error, got: %v", err)
	}
}

func TestValidate_MissingListenerName(t *testing.T) {
	content := `
[tailscale]
hostname = "test"

[[listeners]]
listen = ":9999"
mode = "tcp"
backend = "10.0.0.1:5432"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "name") {
		t.Errorf("expected name error, got: %v", err)
	}
}

func TestValidate_DuplicateListenerName(t *testing.T) {
	content := `
[tailscale]
hostname = "test"

[[listeners]]
name = "dup"
listen = ":9999"
mode = "tcp"
backend = "10.0.0.1:5432"

[[listeners]]
name = "dup"
listen = ":9998"
mode = "tcp"
backend = "10.0.0.2:5432"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate error, got: %v", err)
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	content := `
[tailscale]
hostname = "test"

[[listeners]]
name = "test"
listen = ":9999"
mode = "grpc"
backend = "10.0.0.1:5432"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "mode") {
		t.Errorf("expected mode error, got: %v", err)
	}
}

func TestValidate_MissingListen(t *testing.T) {
	content := `
[tailscale]
hostname = "test"

[[listeners]]
name = "test"
mode = "tcp"
backend = "10.0.0.1:5432"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("expected listen error, got: %v", err)
	}
}

func TestValidate_MissingBackend(t *testing.T) {
	content := `
[tailscale]
hostname = "test"

[[listeners]]
name = "test"
listen = ":9999"
mode = "tcp"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "backend") {
		t.Errorf("expected backend error, got: %v", err)
	}
}

func TestRevalidationConfig_Default(t *testing.T) {
	r := RevalidationConfig{}
	if r.IntervalDuration() != time.Minute {
		t.Errorf("expected default 1m, got %v", r.IntervalDuration())
	}
}

func TestRevalidationConfig_Custom(t *testing.T) {
	r := RevalidationConfig{Interval: "30s"}
	if r.IntervalDuration() != 30*time.Second {
		t.Errorf("expected 30s, got %v", r.IntervalDuration())
	}
}

func TestPostgresAdmin_UserTTLDefault(t *testing.T) {
	p := &PostgresAdmin{}
	if p.UserTTLDuration() != 24*time.Hour {
		t.Errorf("expected default 24h, got %v", p.UserTTLDuration())
	}
}

func TestPostgresAdmin_UserTTLCustom(t *testing.T) {
	p := &PostgresAdmin{UserTTL: "6h"}
	if p.UserTTLDuration() != 6*time.Hour {
		t.Errorf("expected 6h, got %v", p.UserTTLDuration())
	}
}

func TestLoad_TailscaleOAuth(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"
client_secret = "tskey-client-abc123"
advertise_tags = ["tag:server", "tag:prod"]
ephemeral = true

[[listeners]]
name = "test-tcp"
listen = ":9999"
mode = "tcp"
backend = "10.0.0.1:5432"
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tailscale.ClientSecret != "tskey-client-abc123" {
		t.Errorf("client_secret = %q", cfg.Tailscale.ClientSecret)
	}
	if len(cfg.Tailscale.AdvertiseTags) != 2 {
		t.Fatalf("advertise_tags len = %d", len(cfg.Tailscale.AdvertiseTags))
	}
	if cfg.Tailscale.AdvertiseTags[0] != "tag:server" {
		t.Errorf("advertise_tags[0] = %q", cfg.Tailscale.AdvertiseTags[0])
	}
	if !cfg.Tailscale.Ephemeral {
		t.Error("ephemeral should be true")
	}
}

func TestLoad_TailscaleWIF(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"
client_id = "client-123"
id_token = "eyJhbGci..."
audience = "https://login.tailscale.com"
advertise_tags = ["tag:server"]

[[listeners]]
name = "test-tcp"
listen = ":9999"
mode = "tcp"
backend = "10.0.0.1:5432"
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tailscale.ClientID != "client-123" {
		t.Errorf("client_id = %q", cfg.Tailscale.ClientID)
	}
	if cfg.Tailscale.IDToken != "eyJhbGci..." {
		t.Errorf("id_token = %q", cfg.Tailscale.IDToken)
	}
	if cfg.Tailscale.Audience != "https://login.tailscale.com" {
		t.Errorf("audience = %q", cfg.Tailscale.Audience)
	}
}

func TestLoad_TailscaleConflictingAuth(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"
auth_key = "tskey-auth-abc"
client_secret = "tskey-client-abc"
advertise_tags = ["tag:server"]

[[listeners]]
name = "test-tcp"
listen = ":9999"
mode = "tcp"
backend = "10.0.0.1:5432"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "only one auth method") {
		t.Errorf("expected conflicting auth error, got: %v", err)
	}
}

func TestLoad_TailscaleAuthKeyEnvExpansion(t *testing.T) {
	t.Setenv("TEST_TS_AUTHKEY", "tskey-auth-expanded")

	content := `
[tailscale]
hostname = "waypoint-test"
auth_key = "${TEST_TS_AUTHKEY}"

[[listeners]]
name = "test-tcp"
listen = ":9999"
mode = "tcp"
backend = "10.0.0.1:5432"
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tailscale.AuthKey != "tskey-auth-expanded" {
		t.Errorf("auth_key = %q, want tskey-auth-expanded", cfg.Tailscale.AuthKey)
	}
}

func TestLoad_BackendViaTailscale(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "ts-backend"
listen = ":6379"
mode = "tcp"
backend = "my-redis.ts.net:6379"
backend_via_tailscale = true

[[listeners]]
name = "normal"
listen = ":3306"
mode = "tcp"
backend = "10.0.0.1:3306"
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Listeners[0].BackendViaTailscale {
		t.Error("expected BackendViaTailscale to be true for ts-backend listener")
	}
	if cfg.Listeners[1].BackendViaTailscale {
		t.Error("expected BackendViaTailscale to default to false for normal listener")
	}
}

func TestLoad_ServiceField(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "pg-svc"
listen = ":5432"
mode = "postgres"
backend = "10.0.1.10:5432"
service = "svc:waypoint-db"

[[listeners]]
name = "plain"
listen = ":3306"
mode = "tcp"
backend = "10.0.0.1:3306"
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listeners[0].Service != "svc:waypoint-db" {
		t.Errorf("service = %q, want svc:waypoint-db", cfg.Listeners[0].Service)
	}
	if cfg.Listeners[1].Service != "" {
		t.Errorf("service should be empty, got %q", cfg.Listeners[1].Service)
	}
}

func TestValidate_ServiceInvalidPrefix(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "bad-svc"
listen = ":5432"
mode = "tcp"
backend = "10.0.0.1:5432"
service = "waypoint-db"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "svc:") {
		t.Errorf("expected svc: prefix error, got: %v", err)
	}
}

func TestValidate_ServiceHostnameCollision(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-db"

[[listeners]]
name = "pg-svc"
listen = ":5432"
mode = "tcp"
backend = "10.0.0.1:5432"
service = "svc:waypoint-db"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "conflicts with tailscale.hostname") {
		t.Errorf("expected hostname collision error, got: %v", err)
	}
}

func TestValidate_ServiceHostnameNoCollision(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-proxy"

[[listeners]]
name = "pg-svc"
listen = ":5432"
mode = "tcp"
backend = "10.0.0.1:5432"
service = "svc:waypoint-db"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

// --- PortMap parsing tests ---

func TestLoad_PortMap(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "mongo"
mode = "tcp"
backend = "mongo.example.com"
port_map = { "27017" = 27017, "27018" = 27018, "27019" = 27019 }
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Listeners[0]
	if len(l.PortMap) != 3 {
		t.Fatalf("PortMap len = %d, want 3", len(l.PortMap))
	}
	if l.PortMap[27017] != 27017 {
		t.Errorf("PortMap[27017] = %d", l.PortMap[27017])
	}
	if l.PortMap[27018] != 27018 {
		t.Errorf("PortMap[27018] = %d", l.PortMap[27018])
	}
	if l.PortMap[27019] != 27019 {
		t.Errorf("PortMap[27019] = %d", l.PortMap[27019])
	}
	// RawPortMap should still be present with string keys.
	if len(l.RawPortMap) != 3 {
		t.Errorf("RawPortMap len = %d, want 3", len(l.RawPortMap))
	}
}

func TestLoad_PortMap_SinglePort(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "single"
mode = "tcp"
backend = "db.example.com"
port_map = { "5432" = 5432 }
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Listeners[0]
	if len(l.PortMap) != 1 {
		t.Fatalf("PortMap len = %d, want 1", len(l.PortMap))
	}
	if l.PortMap[5432] != 5432 {
		t.Errorf("PortMap[5432] = %d", l.PortMap[5432])
	}
}

func TestLoad_PortMap_DifferentPorts(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "remap"
mode = "tcp"
backend = "db.example.com"
port_map = { "3000" = 5432, "3001" = 5433 }
`
	path := writeTestConfig(t, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Listeners[0]
	if l.PortMap[3000] != 5432 {
		t.Errorf("PortMap[3000] = %d, want 5432", l.PortMap[3000])
	}
	if l.PortMap[3001] != 5433 {
		t.Errorf("PortMap[3001] = %d, want 5433", l.PortMap[3001])
	}
}

func TestLoad_PortMap_InvalidKey(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "bad"
mode = "tcp"
backend = "db.example.com"
port_map = { "notanumber" = 5432 }
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "not a valid port number") {
		t.Errorf("expected 'not a valid port number' error, got: %v", err)
	}
}

// --- PortMap validation tests ---

func TestValidate_PortMap_PostgresMode(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "bad"
mode = "postgres"
backend = "db.example.com"
port_map = { "5432" = 5432 }

[listeners.postgres]
admin_user = "admin"
admin_password = "pass"
admin_database = "postgres"
user_prefix = "wp_"
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "only supported for mode") {
		t.Errorf("expected mode error, got: %v", err)
	}
}

func TestValidate_PortMap_BackendWithPort(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "bad"
mode = "tcp"
backend = "db.example.com:5432"
port_map = { "5432" = 5432 }
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "hostname without port") {
		t.Errorf("expected 'hostname without port' error, got: %v", err)
	}
}

func TestValidate_PortMap_ListenWithPort(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "bad"
listen = ":5432"
mode = "tcp"
backend = "db.example.com"
port_map = { "5432" = 5432 }
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "bind host without port") {
		t.Errorf("expected 'bind host without port' error, got: %v", err)
	}
}

func TestValidate_PortMap_InvalidListenPort(t *testing.T) {
	tests := []struct {
		name    string
		portMap string
		errMsg  string
	}{
		{"zero", `{ "0" = 5432 }`, "invalid listen port"},
		{"too_high", `{ "70000" = 5432 }`, "invalid listen port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "bad"
mode = "tcp"
backend = "db.example.com"
port_map = %s
`, tt.portMap)
			path := writeTestConfig(t, content)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected %q error, got: %v", tt.errMsg, err)
			}
		})
	}
}

func TestValidate_PortMap_InvalidBackendPort(t *testing.T) {
	tests := []struct {
		name    string
		portMap string
		errMsg  string
	}{
		{"zero", `{ "5432" = 0 }`, "invalid backend port"},
		{"too_high", `{ "5432" = 70000 }`, "invalid backend port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "bad"
mode = "tcp"
backend = "db.example.com"
port_map = %s
`, tt.portMap)
			path := writeTestConfig(t, content)
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected %q error, got: %v", tt.errMsg, err)
			}
		})
	}
}

func TestValidate_PortMap_AddressCollision(t *testing.T) {
	content := `
[tailscale]
hostname = "waypoint-test"

[[listeners]]
name = "first"
mode = "tcp"
backend = "db1.example.com"
port_map = { "27017" = 27017 }

[[listeners]]
name = "second"
mode = "tcp"
backend = "db2.example.com"
port_map = { "27017" = 27017 }
`
	path := writeTestConfig(t, content)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "conflicts with") {
		t.Errorf("expected address collision error, got: %v", err)
	}
}

// --- ExpandedBackends tests ---

func TestExpandedBackends_NoPortMap(t *testing.T) {
	l := &ListenerConfig{
		Listen:  ":5432",
		Backend: "10.0.0.1:5432",
	}
	pairs := l.ExpandedBackends()
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].Listen != ":5432" {
		t.Errorf("Listen = %q", pairs[0].Listen)
	}
	if pairs[0].Backend != "10.0.0.1:5432" {
		t.Errorf("Backend = %q", pairs[0].Backend)
	}
}

func TestExpandedBackends_WithPortMap(t *testing.T) {
	l := &ListenerConfig{
		Backend: "mongo.example.com",
		PortMap: map[int]int{27018: 27018, 27017: 27017, 27019: 27019},
	}
	pairs := l.ExpandedBackends()
	if len(pairs) != 3 {
		t.Fatalf("expected 3 pairs, got %d", len(pairs))
	}
	// Should be sorted by listen address.
	expected := []BackendPair{
		{Listen: ":27017", Backend: "mongo.example.com:27017"},
		{Listen: ":27018", Backend: "mongo.example.com:27018"},
		{Listen: ":27019", Backend: "mongo.example.com:27019"},
	}
	for i, want := range expected {
		if pairs[i] != want {
			t.Errorf("pairs[%d] = %+v, want %+v", i, pairs[i], want)
		}
	}
}

func TestExpandedBackends_WithBindHost(t *testing.T) {
	l := &ListenerConfig{
		Listen:  "0.0.0.0",
		Backend: "db.example.com",
		PortMap: map[int]int{5432: 5432},
	}
	pairs := l.ExpandedBackends()
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].Listen != "0.0.0.0:5432" {
		t.Errorf("Listen = %q, want 0.0.0.0:5432", pairs[0].Listen)
	}
	if pairs[0].Backend != "db.example.com:5432" {
		t.Errorf("Backend = %q", pairs[0].Backend)
	}
}

func TestExpandedBackends_DifferentPorts(t *testing.T) {
	l := &ListenerConfig{
		Backend: "db.example.com",
		PortMap: map[int]int{3000: 5432, 3001: 5433},
	}
	pairs := l.ExpandedBackends()
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
	expected := []BackendPair{
		{Listen: ":3000", Backend: "db.example.com:5432"},
		{Listen: ":3001", Backend: "db.example.com:5433"},
	}
	for i, want := range expected {
		if pairs[i] != want {
			t.Errorf("pairs[%d] = %+v, want %+v", i, pairs[i], want)
		}
	}
}

func TestListenerConfig_ListenPort(t *testing.T) {
	tests := []struct {
		listen  string
		want    uint16
		wantErr bool
	}{
		{":5432", 5432, false},
		{"0.0.0.0:3306", 3306, false},
		{":0", 0, false},
		{"invalid", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.listen, func(t *testing.T) {
			l := &ListenerConfig{Listen: tt.listen}
			got, err := l.ListenPort()
			if (err != nil) != tt.wantErr {
				t.Fatalf("ListenPort() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ListenPort() = %d, want %d", got, tt.want)
			}
		})
	}
}
