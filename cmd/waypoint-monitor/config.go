package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/redoapp/waypoint/internal/tsconfig"
)

type MonitorConfig struct {
	Listen    string                   `toml:"listen"`
	Redis     RedisConfig              `toml:"redis"`
	Tailscale tsconfig.TailscaleConfig `toml:"tailscale"`
	SSH       SSHConfig                `toml:"ssh"`
}

type SSHConfig struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
	HostKey string `toml:"host_key"`
	Service string `toml:"service"`
}

type RedisConfig struct {
	Address   string `toml:"address"`
	Password  string `toml:"password"`
	DB        int    `toml:"db"`
	TLS       bool   `toml:"tls"`
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
	if err := cfg.Tailscale.Validate(); err != nil {
		return nil, err
	}
	if cfg.SSH.Listen == "" {
		cfg.SSH.Listen = ":22"
	}
	if cfg.SSH.Service != "" && !strings.HasPrefix(cfg.SSH.Service, "svc:") {
		return nil, fmt.Errorf("ssh.service must start with \"svc:\", got %q", cfg.SSH.Service)
	}

	return &cfg, nil
}

// sshListenPort extracts the numeric port from the SSH listen address.
func (c *MonitorConfig) sshListenPort() (uint16, error) {
	_, portStr, err := net.SplitHostPort(c.SSH.Listen)
	if err != nil {
		return 0, fmt.Errorf("invalid ssh listen address %q: %w", c.SSH.Listen, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port in %q: %w", c.SSH.Listen, err)
	}
	return uint16(port), nil
}
