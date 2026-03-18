package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/tsconfig"
)

type Config struct {
	Tailscale    tsconfig.TailscaleConfig `toml:"tailscale"`
	Redis        RedisConfig              `toml:"redis"`
	Revalidation RevalidationConfig       `toml:"revalidation"`
	Defaults     DefaultsConfig           `toml:"defaults"`
	Metrics      metrics.Config           `toml:"metrics"`
	Listeners    []ListenerConfig         `toml:"listeners"`
}

type RedisConfig struct {
	Address   string `toml:"address"`
	Password  string `toml:"password"`
	DB        int    `toml:"db"`
	KeyPrefix string `toml:"key_prefix"`
}

type RevalidationConfig struct {
	Interval string `toml:"interval"`
}

func (r RevalidationConfig) IntervalDuration() time.Duration {
	d, err := time.ParseDuration(r.Interval)
	if err != nil {
		return time.Minute
	}
	return d
}

type DefaultsConfig struct {
	Limits DefaultLimitsConfig `toml:"limits"`
}

type DefaultLimitsConfig struct {
	MaxConnsTotal int `toml:"max_conns_total"`
}

type ListenerConfig struct {
	Name                string         `toml:"name"`
	Listen              string         `toml:"listen"`
	Mode                string         `toml:"mode"`
	Backend             string         `toml:"backend"`
	BackendViaTailscale bool           `toml:"backend_via_tailscale"`
	Service             string         `toml:"service"`
	Postgres            *PostgresAdmin `toml:"postgres"`
}

// ListenPort extracts the numeric port from the Listen address (e.g. ":5432" → 5432).
func (l *ListenerConfig) ListenPort() (uint16, error) {
	_, portStr, err := net.SplitHostPort(l.Listen)
	if err != nil {
		return 0, fmt.Errorf("invalid listen address %q: %w", l.Listen, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port in %q: %w", l.Listen, err)
	}
	return uint16(port), nil
}

type PostgresAdmin struct {
	AdminUser     string `toml:"admin_user"`
	AdminPassword string `toml:"admin_password"`
	AdminDatabase string `toml:"admin_database"`
	UserPrefix    string `toml:"user_prefix"`
	UserTTL       string `toml:"user_ttl"`
}

func (p *PostgresAdmin) UserTTLDuration() time.Duration {
	d, err := time.ParseDuration(p.UserTTL)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

// Load reads and parses a TOML config file, expanding environment variables
// in string values using ${VAR} syntax.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	expanded := os.Expand(string(data), func(key string) string {
		return os.Getenv(key)
	})

	var cfg Config
	if err := toml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	if cfg.Tailscale.Hostname == "" {
		return fmt.Errorf("tailscale.hostname is required")
	}
	if err := cfg.Tailscale.Validate(); err != nil {
		return err
	}
	if len(cfg.Listeners) == 0 {
		return fmt.Errorf("at least one [[listeners]] is required")
	}
	names := make(map[string]bool)
	for i, l := range cfg.Listeners {
		if l.Name == "" {
			return fmt.Errorf("listeners[%d].name is required", i)
		}
		if names[l.Name] {
			return fmt.Errorf("duplicate listener name %q", l.Name)
		}
		names[l.Name] = true
		if l.Listen == "" {
			return fmt.Errorf("listeners[%d].listen is required", i)
		}
		mode := strings.ToLower(l.Mode)
		if mode != "tcp" && mode != "postgres" {
			return fmt.Errorf("listeners[%d].mode must be 'tcp' or 'postgres', got %q", i, l.Mode)
		}
		if l.Backend == "" {
			return fmt.Errorf("listeners[%d].backend is required", i)
		}
		if l.Service != "" && !strings.HasPrefix(l.Service, "svc:") {
			return fmt.Errorf("listeners[%d].service must start with \"svc:\", got %q", i, l.Service)
		}
	}
	return nil
}
