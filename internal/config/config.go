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
	Advertise           string         `toml:"advertise"`
	BackendViaTailscale bool           `toml:"backend_via_tailscale"`
	BackendTLS          bool           `toml:"tls"`
	PostgresTLSMode     string         `toml:"tls_mode"`
	UseTailscaleTLS     *bool          `toml:"use_tailscale_tls"`
	CertFile            string         `toml:"cert_file"`
	KeyFile             string         `toml:"key_file"`
	Service             string         `toml:"service"`
	Postgres            *PostgresAdmin `toml:"postgres"`
	MongoDB             *MongoDBAdmin  `toml:"mongodb"`
	PortMap             map[int]int    `toml:"-"`
	RawPortMap          map[string]int `toml:"port_map,omitempty"`
}

type TLSMode string

const (
	TLSOff      TLSMode = "off"
	TLSOptional TLSMode = "optional"
	TLSRequire  TLSMode = "require"

	PostgresTLSOff      = TLSOff
	PostgresTLSOptional = TLSOptional
	PostgresTLSRequire  = TLSRequire
)

type PostgresTLSMode = TLSMode

func (l ListenerConfig) EffectiveTLSMode() TLSMode {
	switch strings.ToLower(strings.TrimSpace(l.PostgresTLSMode)) {
	case "", string(TLSOptional):
		return TLSOptional
	case string(TLSOff):
		return TLSOff
	case string(TLSRequire):
		return TLSRequire
	default:
		return TLSMode(strings.ToLower(strings.TrimSpace(l.PostgresTLSMode)))
	}
}

func (l ListenerConfig) EffectivePostgresTLSMode() PostgresTLSMode {
	return l.EffectiveTLSMode()
}

func (l ListenerConfig) EffectiveUseTailscaleTLS() bool {
	return l.UseTailscaleTLS == nil || *l.UseTailscaleTLS
}

// BackendPair holds a resolved listen address and backend address.
type BackendPair struct {
	Listen    string
	Backend   string
	Advertise string
}

// ExpandedBackends returns (listenAddr, backendAddr) pairs.
// For single-port listeners, returns one pair using Listen and Backend directly.
// For multi-port listeners (PortMap set), returns one pair per mapping,
// sorted by listen port for deterministic ordering.
func (l *ListenerConfig) ExpandedBackends() []BackendPair {
	if l.MongoDB != nil && l.MongoDB.HasSRV() {
		return l.expandedMongoSRVBackends()
	}

	if l.MongoDB != nil && len(l.MongoDB.Members) > 0 {
		pairs := make([]BackendPair, 0, len(l.MongoDB.Members))
		for _, member := range l.MongoDB.Members {
			pairs = append(pairs, BackendPair{
				Listen:    member.Listen,
				Backend:   member.Backend,
				Advertise: member.Advertise,
			})
		}
		sort.Slice(pairs, func(i, j int) bool {
			return pairs[i].Listen < pairs[j].Listen
		})
		return pairs
	}

	if len(l.PortMap) == 0 {
		return []BackendPair{{Listen: l.Listen, Backend: l.Backend, Advertise: l.Advertise}}
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

func (l *ListenerConfig) expandedMongoSRVBackends() []BackendPair {
	if l.MongoDB == nil || l.MongoDB.SRVMaxMembers <= 0 {
		return []BackendPair{{Listen: l.Listen, Backend: l.Backend, Advertise: l.Advertise}}
	}

	host, portStr, err := net.SplitHostPort(l.Listen)
	if err != nil {
		return []BackendPair{{Listen: l.Listen, Backend: l.Backend, Advertise: l.Advertise}}
	}
	basePort, err := strconv.Atoi(portStr)
	if err != nil {
		return []BackendPair{{Listen: l.Listen, Backend: l.Backend, Advertise: l.Advertise}}
	}

	pairs := make([]BackendPair, 0, l.MongoDB.SRVMaxMembers)
	for i := 0; i < l.MongoDB.SRVMaxMembers; i++ {
		pairs = append(pairs, BackendPair{
			Listen:    net.JoinHostPort(host, strconv.Itoa(basePort+i)),
			Advertise: l.Advertise,
		})
	}
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
	AdminUser string `toml:"admin_user"`
	// AdminPassword is a secret and must never be serialized off-process
	// (e.g. into the Redis heartbeat). json:"-" guards against accidental marshaling.
	AdminPassword string `toml:"admin_password" json:"-"`
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

// MongoDBAdmin holds admin credentials for MongoDB user provisioning.
type MongoDBAdmin struct {
	AdminUser string `toml:"admin_user"`
	// AdminPassword is a secret and must never be serialized off-process. See PostgresAdmin.
	AdminPassword string          `toml:"admin_password" json:"-"`
	AuthDatabase  string          `toml:"auth_database"` // usually "admin"
	UserPrefix    string          `toml:"user_prefix"`
	UserTTL       string          `toml:"user_ttl"`
	ServiceName   string          `toml:"service_name"` // peer.service override for OTel (default: listener name)
	Topology      string          `toml:"topology"`     // "replicaset" (default), "sharded", or "standalone"
	ReplicaSet    string          `toml:"replica_set"`  // optional replica set name for admin provisioning
	SRV           string          `toml:"srv"`          // optional MongoDB SRV name for backend discovery
	SRVMaxMembers int             `toml:"srv_max_members"`
	Provision     *MongoProvision `toml:"provision"`
	Members       []MongoDBMember `toml:"members"`
}

const (
	MongoProvisionDatabase = "database"
	MongoProvisionStatic   = "static"
)

const (
	MongoTopologyReplicaSet = "replicaset"
	MongoTopologySharded    = "sharded"
	MongoTopologyStandalone = "standalone"
)

// MongoProvision selects how a MongoDB listener obtains backend credentials.
type MongoProvision struct {
	Mode        string            `toml:"mode"`
	StaticUsers []MongoStaticUser `toml:"static_users"`
}

// MongoStaticUser maps an ACL role set to an existing MongoDB/Atlas user.
type MongoStaticUser struct {
	Name     string `toml:"name"`
	Username string `toml:"username"`
	// Password is a secret and must never be serialized off-process. See PostgresAdmin.
	Password     string            `toml:"password" json:"-"`
	AuthDatabase string            `toml:"auth_database"`
	Database     string            `toml:"database"`
	Permissions  []string          `toml:"permissions"`
	Roles        []MongoStaticRole `toml:"roles"`
}

// MongoStaticRole describes one backend role assignment for static user matching.
type MongoStaticRole struct {
	Role string `toml:"role"`
	DB   string `toml:"db"`
}

// MongoDBMember maps one replica set member to a Waypoint listener.
type MongoDBMember struct {
	Backend   string `toml:"backend"`   // backend address as MongoDB advertises it, e.g. mongo1:27017
	Listen    string `toml:"listen"`    // Waypoint bind address for this member, e.g. :27017
	Advertise string `toml:"advertise"` // client-visible proxy address, e.g. waypoint-db:27017
}

func (m *MongoDBAdmin) UserTTLDuration() time.Duration {
	d, err := time.ParseDuration(m.UserTTL)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

func (m *MongoDBAdmin) HasSRV() bool {
	return m != nil && strings.TrimSpace(m.SRV) != ""
}

// EffectiveTopology returns the configured cluster topology, lower-cased and
// defaulting to "replicaset" (which also covers standalone via the provisioner's
// single-seed directConnection behavior) when unset.
func (m *MongoDBAdmin) EffectiveTopology() string {
	if m == nil {
		return MongoTopologyReplicaSet
	}
	t := strings.ToLower(strings.TrimSpace(m.Topology))
	if t == "" {
		return MongoTopologyReplicaSet
	}
	return t
}

// IsSharded reports whether the listener targets a sharded cluster (mongos
// routers) rather than a replica set or standalone server.
func (m *MongoDBAdmin) IsSharded() bool {
	return m.EffectiveTopology() == MongoTopologySharded
}

func (m *MongoDBAdmin) EffectiveProvisionMode() string {
	if m == nil || m.Provision == nil {
		return MongoProvisionDatabase
	}
	mode := strings.ToLower(strings.TrimSpace(m.Provision.Mode))
	if mode == "" {
		if len(m.Provision.StaticUsers) > 0 {
			return MongoProvisionStatic
		}
		return MongoProvisionDatabase
	}
	return mode
}

func (m *MongoDBAdmin) EffectiveAuthDatabase() string {
	if m == nil || strings.TrimSpace(m.AuthDatabase) == "" {
		return "admin"
	}
	return m.AuthDatabase
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
		if mode != "tcp" && mode != "postgres" && mode != "mongodb" {
			return fmt.Errorf("listeners[%d].mode must be 'tcp', 'postgres', or 'mongodb', got %q", i, l.Mode)
		}
		if l.MongoDB.HasSRV() && mode != "mongodb" {
			return fmt.Errorf("listeners[%d]: mongodb.srv is only supported for mode %q, got %q", i, "mongodb", l.Mode)
		}
		hasMongoMembers := mode == "mongodb" && l.MongoDB != nil && len(l.MongoDB.Members) > 0
		hasMongoSRV := mode == "mongodb" && l.MongoDB.HasSRV()
		if l.Backend == "" && !hasMongoMembers && !hasMongoSRV {
			return fmt.Errorf("listeners[%d].backend is required", i)
		}
		if hasMongoMembers && l.Backend == "" {
			l.Backend = l.MongoDB.Members[0].Backend
			cfg.Listeners[i] = l
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
				return fmt.Errorf("listeners[%d]: port_map is only supported for mode %q, got %q", i, "tcp", l.Mode)
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
		} else if !hasMongoMembers {
			if l.Listen == "" {
				return fmt.Errorf("listeners[%d].listen is required", i)
			}
		}

		if l.Advertise != "" {
			if hasMongoSRV {
				if err := validateAdvertiseHostOrAddr(l.Advertise); err != nil {
					return fmt.Errorf("listeners[%d].advertise must be host or host:port, got %q: %w", i, l.Advertise, err)
				}
			} else if _, _, err := net.SplitHostPort(l.Advertise); err != nil {
				return fmt.Errorf("listeners[%d].advertise must be host:port, got %q: %w", i, l.Advertise, err)
			}
		}

		if l.MongoDB != nil && l.MongoDB.HasSRV() {
			if len(l.MongoDB.Members) > 0 {
				return fmt.Errorf("listeners[%d]: mongodb.srv cannot be combined with mongodb.members", i)
			}
			if l.MongoDB.SRVMaxMembers <= 0 {
				return fmt.Errorf("listeners[%d].mongodb.srv_max_members must be greater than zero when srv is set", i)
			}
			if l.Service != "" && l.Advertise == "" {
				return fmt.Errorf("listeners[%d].advertise is required when service is set with mongodb.srv", i)
			}
			if _, portStr, err := net.SplitHostPort(l.Listen); err != nil {
				return fmt.Errorf("listeners[%d].listen must be host:port when mongodb.srv is set, got %q: %w", i, l.Listen, err)
			} else {
				port, err := strconv.ParseUint(portStr, 10, 16)
				if err != nil {
					return fmt.Errorf("listeners[%d].listen has invalid port %q: %w", i, portStr, err)
				}
				if int(port)+l.MongoDB.SRVMaxMembers-1 > 65535 {
					return fmt.Errorf("listeners[%d].mongodb.srv_max_members overflows listen port range", i)
				}
			}
		}

		if l.MongoDB != nil && len(l.MongoDB.Members) > 0 {
			if mode != "mongodb" {
				return fmt.Errorf("listeners[%d]: mongodb.members is only supported for mode %q, got %q", i, "mongodb", l.Mode)
			}
			if len(l.PortMap) > 0 {
				return fmt.Errorf("listeners[%d]: mongodb.members cannot be combined with port_map", i)
			}
			for j, member := range l.MongoDB.Members {
				if member.Backend == "" {
					return fmt.Errorf("listeners[%d].mongodb.members[%d].backend is required", i, j)
				}
				if member.Listen == "" {
					return fmt.Errorf("listeners[%d].mongodb.members[%d].listen is required", i, j)
				}
				if _, _, err := net.SplitHostPort(member.Backend); err != nil {
					return fmt.Errorf("listeners[%d].mongodb.members[%d].backend must be host:port, got %q: %w", i, j, member.Backend, err)
				}
				if _, _, err := net.SplitHostPort(member.Listen); err != nil {
					return fmt.Errorf("listeners[%d].mongodb.members[%d].listen must be host:port, got %q: %w", i, j, member.Listen, err)
				}
				if member.Advertise != "" {
					if _, _, err := net.SplitHostPort(member.Advertise); err != nil {
						return fmt.Errorf("listeners[%d].mongodb.members[%d].advertise must be host:port, got %q: %w", i, j, member.Advertise, err)
					}
				}
				if l.Service != "" && member.Advertise == "" && l.Advertise == "" {
					return fmt.Errorf("listeners[%d].mongodb.members[%d].advertise is required when service is set", i, j)
				}
			}
		}

		if l.MongoDB != nil {
			switch l.MongoDB.EffectiveTopology() {
			case MongoTopologyReplicaSet, MongoTopologyStandalone:
			case MongoTopologySharded:
				if mode != "mongodb" {
					return fmt.Errorf("listeners[%d]: mongodb.topology is only supported for mode %q, got %q", i, "mongodb", l.Mode)
				}
				if strings.TrimSpace(l.MongoDB.ReplicaSet) != "" {
					return fmt.Errorf("listeners[%d]: mongodb.replica_set cannot be combined with topology %q", i, MongoTopologySharded)
				}
				if len(l.MongoDB.Members) == 0 && !l.MongoDB.HasSRV() {
					return fmt.Errorf("listeners[%d]: mongodb.topology %q requires mongodb.members (mongos routers) or mongodb.srv", i, MongoTopologySharded)
				}
			default:
				return fmt.Errorf("listeners[%d]: mongodb.topology must be one of %q, %q, %q, got %q", i, MongoTopologyReplicaSet, MongoTopologySharded, MongoTopologyStandalone, l.MongoDB.Topology)
			}

			if err := validateMongoProvision(i, l.MongoDB); err != nil {
				return err
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
		if l.PostgresTLSMode != "" {
			switch l.EffectiveTLSMode() {
			case TLSOff, TLSOptional, TLSRequire:
			default:
				return fmt.Errorf("listeners[%d].tls_mode must be one of %q, %q, or %q, got %q", i, TLSOff, TLSOptional, TLSRequire, l.PostgresTLSMode)
			}
		}
		if (l.CertFile == "") != (l.KeyFile == "") {
			return fmt.Errorf("listeners[%d] must set both cert_file and key_file together", i)
		}
		if (l.CertFile != "" || l.KeyFile != "") && !supportsClientTLS(mode) {
			return fmt.Errorf("listeners[%d].cert_file and key_file are only supported for mode \"postgres\" or \"mongodb\"", i)
		}
		if l.PostgresTLSMode != "" && !supportsClientTLS(mode) {
			return fmt.Errorf("listeners[%d].tls_mode is only supported for mode \"postgres\" or \"mongodb\"", i)
		}
		if l.UseTailscaleTLS != nil && !supportsClientTLS(mode) {
			return fmt.Errorf("listeners[%d].use_tailscale_tls is only supported for mode \"postgres\" or \"mongodb\"", i)
		}
	}
	return nil
}

func validateMongoProvision(listenerIndex int, m *MongoDBAdmin) error {
	mode := m.EffectiveProvisionMode()
	switch mode {
	case MongoProvisionDatabase, MongoProvisionStatic:
	default:
		return fmt.Errorf("listeners[%d].mongodb.provision.mode must be one of %q or %q, got %q",
			listenerIndex, MongoProvisionDatabase, MongoProvisionStatic, m.Provision.Mode)
	}

	if mode != MongoProvisionStatic {
		return nil
	}
	if m.Provision == nil || len(m.Provision.StaticUsers) == 0 {
		return fmt.Errorf("listeners[%d].mongodb.provision.static_users is required when mode is %q", listenerIndex, MongoProvisionStatic)
	}

	for i, user := range m.Provision.StaticUsers {
		prefix := fmt.Sprintf("listeners[%d].mongodb.provision.static_users[%d]", listenerIndex, i)
		if strings.TrimSpace(user.Username) == "" {
			return fmt.Errorf("%s.username is required", prefix)
		}
		if user.Password == "" {
			return fmt.Errorf("%s.password is required", prefix)
		}
		if len(user.Roles) > 0 {
			if len(user.Permissions) > 0 || strings.TrimSpace(user.Database) != "" {
				return fmt.Errorf("%s.roles cannot be combined with database or permissions", prefix)
			}
			for j, role := range user.Roles {
				if strings.TrimSpace(role.Role) == "" {
					return fmt.Errorf("%s.roles[%d].role is required", prefix, j)
				}
				if strings.TrimSpace(role.DB) == "" {
					return fmt.Errorf("%s.roles[%d].db is required", prefix, j)
				}
			}
			continue
		}
		if len(user.Permissions) == 0 {
			return fmt.Errorf("%s.permissions or roles is required", prefix)
		}
		for _, perm := range user.Permissions {
			if !validMongoPreset(perm) {
				return fmt.Errorf("%s.permissions contains unknown preset %q; valid presets: readonly, readwrite, admin", prefix, perm)
			}
		}
	}
	return nil
}

func validMongoPreset(preset string) bool {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "readonly", "readwrite", "admin":
		return true
	default:
		return false
	}
}

func supportsClientTLS(mode string) bool {
	return mode == "postgres" || mode == "mongodb"
}

func validateAdvertiseHostOrAddr(advertise string) error {
	if strings.TrimSpace(advertise) == "" {
		return fmt.Errorf("empty advertise")
	}
	if _, _, err := net.SplitHostPort(advertise); err == nil {
		return nil
	}
	if strings.Contains(advertise, ":") {
		return fmt.Errorf("invalid host:port")
	}
	if strings.Contains(advertise, "/") {
		return fmt.Errorf("invalid host")
	}
	return nil
}
