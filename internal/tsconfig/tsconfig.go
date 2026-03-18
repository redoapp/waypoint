package tsconfig

import (
	"fmt"
	"strings"

	"tailscale.com/tsnet"

	// Register feature hooks for OAuth and WIF auth methods.
	_ "tailscale.com/feature/identityfederation"
	_ "tailscale.com/feature/oauthkey"
)

// TailscaleConfig holds all Tailscale connection settings. Only one auth
// method should be configured: auth_key, client_secret (OAuth), or
// client_id+id_token (WIF). When no auth fields are set, tsnet falls back
// to its built-in environment variable handling (TS_AUTHKEY, etc.).
type TailscaleConfig struct {
	Hostname      string   `toml:"hostname"`
	StateDir      string   `toml:"state_dir"`
	AuthKey       string   `toml:"auth_key"`
	ControlURL    string   `toml:"control_url"`
	Ephemeral     bool     `toml:"ephemeral"`
	AdvertiseTags []string `toml:"advertise_tags"`
	// OAuth client secret (starts with "tskey-client-").
	ClientSecret string `toml:"client_secret"`
	// Workload Identity Federation fields.
	ClientID string `toml:"client_id"`
	IDToken  string `toml:"id_token"`
	Audience string `toml:"audience"`
}

// Validate checks that at most one auth method is configured and that
// required companion fields are present.
func (c *TailscaleConfig) Validate() error {
	methods := 0
	if c.AuthKey != "" {
		methods++
	}
	if c.ClientSecret != "" {
		methods++
	}
	wif := c.IDToken != "" || c.Audience != ""
	if wif {
		methods++
	}

	if methods > 1 {
		return fmt.Errorf("tailscale: only one auth method may be set (auth_key, client_secret, or id_token/audience)")
	}

	if c.ClientSecret != "" && len(c.AdvertiseTags) == 0 {
		return fmt.Errorf("tailscale: advertise_tags is required when using client_secret (OAuth)")
	}

	if wif {
		if c.ClientID == "" {
			return fmt.Errorf("tailscale: client_id is required when using id_token/audience (WIF)")
		}
		if len(c.AdvertiseTags) == 0 {
			return fmt.Errorf("tailscale: advertise_tags is required when using id_token/audience (WIF)")
		}
	}

	if len(c.AdvertiseTags) > 0 {
		for _, tag := range c.AdvertiseTags {
			if !strings.HasPrefix(tag, "tag:") {
				return fmt.Errorf("tailscale: advertise_tags entries must start with \"tag:\", got %q", tag)
			}
		}
	}

	return nil
}

// Apply sets non-zero config fields on the given tsnet.Server, leaving
// zero-value fields untouched so tsnet's built-in env var fallbacks still work.
func (c *TailscaleConfig) Apply(srv *tsnet.Server) {
	if c.Hostname != "" {
		srv.Hostname = c.Hostname
	}
	if c.StateDir != "" {
		srv.Dir = c.StateDir
	}
	if c.AuthKey != "" {
		srv.AuthKey = c.AuthKey
	}
	if c.ControlURL != "" {
		srv.ControlURL = c.ControlURL
	}
	if c.Ephemeral {
		srv.Ephemeral = true
	}
	if len(c.AdvertiseTags) > 0 {
		srv.AdvertiseTags = c.AdvertiseTags
	}
	if c.ClientSecret != "" {
		srv.ClientSecret = c.ClientSecret
	}
	if c.ClientID != "" {
		srv.ClientID = c.ClientID
	}
	if c.IDToken != "" {
		srv.IDToken = c.IDToken
	}
	if c.Audience != "" {
		srv.Audience = c.Audience
	}
}
