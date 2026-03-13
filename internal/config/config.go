package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Tailscale    TailscaleConfig    `toml:"tailscale"`
	Redis        RedisConfig        `toml:"redis"`
	Revalidation RevalidationConfig `toml:"revalidation"`
	Defaults     DefaultsConfig     `toml:"defaults"`
	Listeners    []ListenerConfig   `toml:"listeners"`
}

type TailscaleConfig struct {
	Hostname string `toml:"hostname"`
	StateDir string `toml:"state_dir"`
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
	Name     string         `toml:"name"`
	Listen   string         `toml:"listen"`
	Mode     string         `toml:"mode"`
	Backend  string         `toml:"backend"`
	Postgres *PostgresAdmin `toml:"postgres"`
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
	}
	return nil
}
