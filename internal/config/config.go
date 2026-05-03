package config

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/tsconfig"
)

type Config struct {
	LogLevel     string                   `toml:"log_level"`
	Tailscale    tsconfig.TailscaleConfig `toml:"tailscale"`
	Redis        RedisConfig              `toml:"redis"`
	Revalidation RevalidationConfig       `toml:"revalidation"`
	Defaults     DefaultsConfig           `toml:"defaults"`
	Metrics      metrics.Config           `toml:"metrics"`
	Provisioning ProvisioningConfig       `toml:"provisioning"`
	Listeners    []ListenerConfig         `toml:"listeners"`
}

type ProvisioningConfig struct {
	AllowRawSQL *bool `toml:"allow_raw_sql"` // nil = true (default)
}

type RedisConfig struct {
	Address     string `toml:"address"`
	Password    string `toml:"password"`
	DB          int    `toml:"db"`
	TLS         bool   `toml:"tls"`
	KeyPrefix   string `toml:"key_prefix"`
	ServiceName string `toml:"service_name"` // peer.service for OTel traces (default: "redis")
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
	BackendTLS          bool           `toml:"tls"`
	Service             string         `toml:"service"`
	Postgres            *PostgresAdmin `toml:"postgres"`
	PortMap             map[int]int    `toml:"-"`
	RawPortMap          map[string]int `toml:"port_map,omitempty"`
}

// BackendPair holds a resolved listen address and backend address.
type BackendPair struct {
	Listen  string
	Backend string
}

// ExpandedBackends returns (listenAddr, backendAddr) pairs.
// For single-port listeners, returns one pair using Listen and Backend directly.
// For multi-port listeners (PortMap set), returns one pair per mapping,
// sorted by listen port for deterministic ordering.
func (l *ListenerConfig) ExpandedBackends() []BackendPair {
	if len(l.PortMap) == 0 {
		return []BackendPair{{Listen: l.Listen, Backend: l.Backend}}
	}

	// Extract bind host from Listen field (e.g., "0.0.0.0" → "0.0.0.0", "" → "").
	bindHost := l.Listen

	pairs := make([]BackendPair, 0, len(l.PortMap))
	for listenPort, backendPort := range l.PortMap {
		pairs = append(pairs, BackendPair{
			Listen:  net.JoinHostPort(bindHost, strconv.Itoa(listenPort)),
			Backend: net.JoinHostPort(l.Backend, strconv.Itoa(backendPort)),
		})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Listen < pairs[j].Listen
	})
	return pairs
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
	AllowRawSQL   *bool  `toml:"allow_raw_sql"` // nil = use global
	ServiceName   string `toml:"service_name"`  // peer.service override for OTel (default: listener name)
}

// AllowRawSQLResolved returns whether raw SQL is allowed for this listener,
// resolving per-listener → global → default (true).
func AllowRawSQLResolved(listener *PostgresAdmin, global *ProvisioningConfig) bool {
	if listener != nil && listener.AllowRawSQL != nil {
		return *listener.AllowRawSQL
	}
	if global != nil && global.AllowRawSQL != nil {
		return *global.AllowRawSQL
	}
	return true
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
	listenAddrs := make(map[string]string) // listen addr → listener name (for collision detection)
	for i, l := range cfg.Listeners {
		if l.Name == "" {
			return fmt.Errorf("listeners[%d].name is required", i)
		}
		if names[l.Name] {
			return fmt.Errorf("duplicate listener name %q", l.Name)
		}
		names[l.Name] = true

		mode := strings.ToLower(l.Mode)
		if mode != "tcp" && mode != "postgres" {
			return fmt.Errorf("listeners[%d].mode must be 'tcp' or 'postgres', got %q", i, l.Mode)
		}
		if l.Backend == "" {
			return fmt.Errorf("listeners[%d].backend is required", i)
		}

		// Convert string-keyed port_map (TOML limitation) to int-keyed map.
		if len(l.RawPortMap) > 0 {
			l.PortMap = make(map[int]int, len(l.RawPortMap))
			for k, v := range l.RawPortMap {
				port, err := strconv.Atoi(k)
				if err != nil {
					return fmt.Errorf("listeners[%d]: port_map key %q is not a valid port number", i, k)
				}
				l.PortMap[port] = v
			}
			cfg.Listeners[i] = l
		}

		hasPortMap := len(l.PortMap) > 0

		if hasPortMap {
			if mode != "tcp" {
				return fmt.Errorf("listeners[%d]: port_map is only supported for mode \"tcp\", got %q", i, l.Mode)
			}
			// Backend must be a host without port when port_map is set.
			if _, _, err := net.SplitHostPort(l.Backend); err == nil {
				return fmt.Errorf("listeners[%d]: backend must be a hostname without port when port_map is set (got %q)", i, l.Backend)
			}
			// Listen field (if set) must be a bind host without port.
			if l.Listen != "" {
				if _, _, err := net.SplitHostPort(l.Listen); err == nil {
					return fmt.Errorf("listeners[%d]: listen must be a bind host without port when port_map is set, or omit it", i)
				}
			}
			for lp, bp := range l.PortMap {
				if lp < 1 || lp > 65535 {
					return fmt.Errorf("listeners[%d]: invalid listen port %d in port_map", i, lp)
				}
				if bp < 1 || bp > 65535 {
					return fmt.Errorf("listeners[%d]: invalid backend port %d in port_map", i, bp)
				}
			}
		} else {
			if l.Listen == "" {
				return fmt.Errorf("listeners[%d].listen is required", i)
			}
		}

		// Check for listen address collisions across all listeners.
		for _, be := range l.ExpandedBackends() {
			if existing, ok := listenAddrs[be.Listen]; ok {
				return fmt.Errorf("listeners[%d] (%q): listen address %q conflicts with listener %q", i, l.Name, be.Listen, existing)
			}
			listenAddrs[be.Listen] = l.Name
		}

		if l.Service != "" && !strings.HasPrefix(l.Service, "svc:") {
			return fmt.Errorf("listeners[%d].service must start with \"svc:\", got %q", i, l.Service)
		}
		if l.Service != "" && strings.TrimPrefix(l.Service, "svc:") == cfg.Tailscale.Hostname {
			return fmt.Errorf("listeners[%d].service %q conflicts with tailscale.hostname %q — the service name (without \"svc:\" prefix) must differ from the hostname to avoid DNS shadowing", i, l.Service, cfg.Tailscale.Hostname)
		}
	}
	return nil
}
