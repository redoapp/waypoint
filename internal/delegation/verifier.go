package delegation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/redoapp/waypoint/internal/auth"
)

const TokenType = "waypoint-delegation+jwt"

// Config is the server-owned delegation trust and profile registry.
type Config struct {
	Issuer             string             `toml:"issuer"`
	Audience           string             `toml:"audience"`
	Keys               map[string]string  `toml:"keys"`
	Profiles           map[string]Profile `toml:"profiles"`
	PrefaceTimeout     string             `toml:"preface_timeout"`
	MaxCredentialBytes int                `toml:"max_credential_bytes"`
}

// Profile maps a signed profile name to server-owned grants and limits.
type Profile struct {
	Backend  string          `toml:"backend"`
	Postgres *auth.PGCap     `toml:"postgres"`
	Limits   *auth.LimitsCap `toml:"limits"`
}

func (c Config) EffectivePrefaceTimeout() time.Duration {
	if c.PrefaceTimeout == "" {
		return DefaultPrefaceTimeout
	}
	d, err := time.ParseDuration(c.PrefaceTimeout)
	if err != nil || d <= 0 {
		return DefaultPrefaceTimeout
	}
	return d
}

func (c Config) EffectiveMaxCredentialBytes() int {
	if c.MaxCredentialBytes == 0 {
		return DefaultMaxCredentialSize
	}
	return c.MaxCredentialBytes
}

// ValidateConfig rejects incomplete trust configuration before listeners start.
func ValidateConfig(c Config, listenerName string) error {
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("issuer is required")
	}
	if strings.TrimSpace(c.Audience) == "" {
		return errors.New("audience is required")
	}
	if len(c.Keys) == 0 {
		return errors.New("at least one verification key is required")
	}
	for kid, encoded := range c.Keys {
		if strings.TrimSpace(kid) == "" {
			return errors.New("verification key kid is required")
		}
		key, err := jwt.ParseECPublicKeyFromPEM([]byte(encoded))
		if err != nil {
			return fmt.Errorf("parse verification key %q: %w", kid, err)
		}
		if key.Curve != elliptic.P256() {
			return fmt.Errorf("verification key %q must use the P-256 curve", kid)
		}
	}
	if len(c.Profiles) == 0 {
		return errors.New("at least one delegation profile is required")
	}
	for name, profile := range c.Profiles {
		if strings.TrimSpace(name) == "" {
			return errors.New("delegation profile name is required")
		}
		if profile.Backend != listenerName {
			return fmt.Errorf("profile %q backend must equal listener name %q", name, listenerName)
		}
		if profile.Postgres == nil || len(profile.Postgres.Databases) == 0 {
			return fmt.Errorf("profile %q must configure at least one postgres database", name)
		}
	}
	if c.MaxCredentialBytes < 0 || c.MaxCredentialBytes > DefaultMaxCredentialSize {
		return fmt.Errorf("max_credential_bytes must be between 1 and %d when set", DefaultMaxCredentialSize)
	}
	if c.PrefaceTimeout != "" {
		d, err := time.ParseDuration(c.PrefaceTimeout)
		if err != nil || d <= 0 || d > DefaultPrefaceTimeout {
			return fmt.Errorf("preface_timeout must be greater than zero and at most %s", DefaultPrefaceTimeout)
		}
	}
	return nil
}

// ReplayStore atomically consumes a credential identifier across replicas.
type ReplayStore interface {
	ConsumeDelegationJTI(ctx context.Context, issuer, jti string, expiresAt time.Time) (bool, error)
}

type claims struct {
	Backend string `json:"backend"`
	Profile string `json:"profile"`
	jwt.RegisteredClaims
}

// Verifier validates credentials and resolves them to an authorized session.
type Verifier struct {
	config Config
	keys   map[string]*ecdsa.PublicKey
	replay ReplayStore
	now    func() time.Time
}

func NewVerifier(config Config, replay ReplayStore) (*Verifier, error) {
	if replay == nil {
		return nil, errors.New("delegation replay store is required")
	}
	if err := ValidateConfig(config, profileBackend(config.Profiles)); err != nil {
		return nil, err
	}
	keys := make(map[string]*ecdsa.PublicKey, len(config.Keys))
	for kid, encoded := range config.Keys {
		key, err := jwt.ParseECPublicKeyFromPEM([]byte(encoded))
		if err != nil {
			return nil, fmt.Errorf("parse verification key %q: %w", kid, err)
		}
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("verification key %q must use the P-256 curve", kid)
		}
		keys[kid] = key
	}
	return &Verifier{config: config, keys: keys, replay: replay, now: time.Now}, nil
}

func profileBackend(profiles map[string]Profile) string {
	for _, profile := range profiles {
		return profile.Backend
	}
	return ""
}

// Verify authenticates a one-time credential for the requested listener.
func (v *Verifier) Verify(ctx context.Context, raw, backend string, transport auth.TransportIdentity) (*auth.AuthorizedSession, error) {
	parsedClaims := &claims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer(v.config.Issuer),
		jwt.WithAudience(v.config.Audience),
		jwt.WithLeeway(5*time.Second),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
		jwt.WithStrictDecoding(),
		jwt.WithTimeFunc(v.now),
	)
	token, err := parser.ParseWithClaims(raw, parsedClaims, func(token *jwt.Token) (any, error) {
		if token.Header["typ"] != TokenType {
			return nil, fmt.Errorf("unexpected token type")
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("credential does not identify a signing key")
		}
		key := v.keys[kid]
		if key == nil {
			return nil, fmt.Errorf("credential signing key %q is not trusted", kid)
		}
		return key, nil
	})
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("verify delegation credential: %w", err)
	}
	if parsedClaims.Subject == "" || parsedClaims.ID == "" || parsedClaims.IssuedAt == nil || parsedClaims.ExpiresAt == nil || parsedClaims.Backend == "" || parsedClaims.Profile == "" {
		return nil, errors.New("delegation credential is missing required claims")
	}

	now := v.now()
	issuedAt := parsedClaims.IssuedAt.Time
	expiresAt := parsedClaims.ExpiresAt.Time
	if issuedAt.After(now.Add(5*time.Second)) || issuedAt.Before(now.Add(-65*time.Second)) {
		return nil, errors.New("delegation credential was not issued within the previous 60 seconds")
	}
	if !expiresAt.After(issuedAt) || expiresAt.After(issuedAt.Add(time.Hour)) {
		return nil, errors.New("delegation credential lifetime must be positive and at most one hour")
	}

	consumed, err := v.replay.ConsumeDelegationJTI(ctx, parsedClaims.Issuer, parsedClaims.ID, expiresAt.Add(5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("consume delegation credential: %w", err)
	}
	if !consumed {
		return nil, errors.New("delegation credential has already been used")
	}
	if parsedClaims.Backend != backend {
		return nil, fmt.Errorf("credential backend %q is not valid for listener %q", parsedClaims.Backend, backend)
	}
	profile, ok := v.config.Profiles[parsedClaims.Profile]
	if !ok || profile.Backend != backend {
		return nil, fmt.Errorf("delegation profile %q is not authorized for listener %q", parsedClaims.Profile, backend)
	}

	quotaIdentity := namespacedHash("delegated-quota", parsedClaims.Issuer, parsedClaims.Subject)
	provisioningIdentity := namespacedHash("delegated-role", parsedClaims.Issuer, parsedClaims.Subject)
	roleScope := namespacedHash("delegated-scope", backend, parsedClaims.Profile)
	rule := auth.CapRule{
		Limits: profile.Limits,
		Backends: map[string]auth.BackendCap{
			backend: {PG: profile.Postgres},
		},
	}
	permissions := make([]string, 0)
	for _, database := range profile.Postgres.Databases {
		permissions = append(permissions, database.Permissions...)
	}
	return auth.NewDelegatedSession(auth.DelegatedSessionParams{
		Authorization: &auth.AuthResult{
			LoginName:    parsedClaims.Subject,
			NodeName:     "delegated",
			Permissions:  permissions,
			Limits:       auth.ResolveLimits(profile.Limits),
			MatchedRules: []auth.CapRule{rule},
		},
		Principal:     parsedClaims.Subject,
		QuotaIdentity: quotaIdentity,
		Provisioning: auth.ProvisioningIdentity{
			LoginName: provisioningIdentity,
			NodeName:  "agent",
			RoleScope: roleScope,
		},
		Transport:           transport,
		CredentialExpiresAt: expiresAt,
		Backend:             backend,
		Profile:             parsedClaims.Profile,
	})
}

func namespacedHash(namespace string, values ...string) string {
	h := sha256.New()
	h.Write([]byte(namespace))
	for _, value := range values {
		h.Write([]byte{0})
		h.Write([]byte(value))
	}
	return namespace + ":" + hex.EncodeToString(h.Sum(nil))
}
