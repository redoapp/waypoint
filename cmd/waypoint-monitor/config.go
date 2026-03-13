package main

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type MonitorConfig struct {
	Listen    string          `toml:"listen"`
	Redis     RedisConfig     `toml:"redis"`
	Tailscale TailscaleConfig `toml:"tailscale"`
	SSH       SSHConfig       `toml:"ssh"`
}

type TailscaleConfig struct {
	Hostname string `toml:"hostname"`
	StateDir string `toml:"state_dir"`
}

type SSHConfig struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
	HostKey string `toml:"host_key"`
}

type RedisConfig struct {
	Address   string `toml:"address"`
	Password  string `toml:"password"`
	DB        int    `toml:"db"`
	KeyPrefix string `toml:"key_prefix"`
}

func loadConfig(path string) (*MonitorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	expanded := os.Expand(string(data), func(key string) string {
		return os.Getenv(key)
	})

	var cfg MonitorConfig
	if err := toml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.Redis.Address == "" {
		cfg.Redis.Address = "localhost:6379"
	}
	if cfg.Redis.KeyPrefix == "" {
		cfg.Redis.KeyPrefix = "waypoint:"
	}
	if cfg.Tailscale.Hostname == "" {
		cfg.Tailscale.Hostname = "waypoint-mgr"
	}
	if cfg.SSH.Listen == "" {
		cfg.SSH.Listen = ":22"
	}

	return &cfg, nil
}
