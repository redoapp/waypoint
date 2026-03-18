package tsconfig

import (
	"testing"

	"tailscale.com/tsnet"
)

func TestValidate_Empty(t *testing.T) {
	c := &TailscaleConfig{}
	if err := c.Validate(); err != nil {
		t.Fatalf("empty config should be valid: %v", err)
	}
}

func TestValidate_AuthKey(t *testing.T) {
	c := &TailscaleConfig{AuthKey: "tskey-auth-abc123"}
	if err := c.Validate(); err != nil {
		t.Fatalf("auth_key only should be valid: %v", err)
	}
}

func TestValidate_OAuth(t *testing.T) {
	c := &TailscaleConfig{
		ClientSecret:  "tskey-client-abc123",
		AdvertiseTags: []string{"tag:server"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("oauth with tags should be valid: %v", err)
	}
}

func TestValidate_OAuthMissingTags(t *testing.T) {
	c := &TailscaleConfig{ClientSecret: "tskey-client-abc123"}
	if err := c.Validate(); err == nil {
		t.Fatal("oauth without tags should fail")
	}
}

func TestValidate_WIF(t *testing.T) {
	c := &TailscaleConfig{
		ClientID:      "client-123",
		IDToken:       "eyJhbGci...",
		AdvertiseTags: []string{"tag:server"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("wif with tags should be valid: %v", err)
	}
}

func TestValidate_WIFAudienceOnly(t *testing.T) {
	c := &TailscaleConfig{
		ClientID:      "client-123",
		Audience:      "https://login.tailscale.com",
		AdvertiseTags: []string{"tag:server"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("wif with audience should be valid: %v", err)
	}
}

func TestValidate_WIFMissingClientID(t *testing.T) {
	c := &TailscaleConfig{
		IDToken:       "eyJhbGci...",
		AdvertiseTags: []string{"tag:server"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("wif without client_id should fail")
	}
}

func TestValidate_WIFMissingTags(t *testing.T) {
	c := &TailscaleConfig{
		ClientID: "client-123",
		IDToken:  "eyJhbGci...",
	}
	if err := c.Validate(); err == nil {
		t.Fatal("wif without tags should fail")
	}
}

func TestValidate_ConflictingMethods(t *testing.T) {
	cases := []struct {
		name string
		cfg  TailscaleConfig
	}{
		{
			name: "authkey+oauth",
			cfg: TailscaleConfig{
				AuthKey:       "tskey-auth-abc",
				ClientSecret:  "tskey-client-abc",
				AdvertiseTags: []string{"tag:server"},
			},
		},
		{
			name: "authkey+wif",
			cfg: TailscaleConfig{
				AuthKey:       "tskey-auth-abc",
				ClientID:      "client-123",
				IDToken:       "eyJ...",
				AdvertiseTags: []string{"tag:server"},
			},
		},
		{
			name: "oauth+wif",
			cfg: TailscaleConfig{
				ClientSecret:  "tskey-client-abc",
				ClientID:      "client-123",
				IDToken:       "eyJ...",
				AdvertiseTags: []string{"tag:server"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Fatal("conflicting methods should fail")
			}
		})
	}
}

func TestValidate_BadTagPrefix(t *testing.T) {
	c := &TailscaleConfig{
		AuthKey:       "tskey-auth-abc",
		AdvertiseTags: []string{"server"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("tags without tag: prefix should fail")
	}
}

func TestApply_AllFields(t *testing.T) {
	c := &TailscaleConfig{
		Hostname:      "my-host",
		StateDir:      "/tmp/ts",
		AuthKey:       "tskey-auth-abc",
		ControlURL:    "https://controlplane.example.com",
		Ephemeral:     true,
		AdvertiseTags: []string{"tag:server"},
		ClientSecret:  "tskey-client-abc",
		ClientID:      "client-123",
		IDToken:       "eyJ...",
		Audience:      "https://login.tailscale.com",
	}
	srv := new(tsnet.Server)
	c.Apply(srv)

	if srv.Hostname != "my-host" {
		t.Errorf("Hostname = %q", srv.Hostname)
	}
	if srv.Dir != "/tmp/ts" {
		t.Errorf("Dir = %q", srv.Dir)
	}
	if srv.AuthKey != "tskey-auth-abc" {
		t.Errorf("AuthKey = %q", srv.AuthKey)
	}
	if srv.ControlURL != "https://controlplane.example.com" {
		t.Errorf("ControlURL = %q", srv.ControlURL)
	}
	if !srv.Ephemeral {
		t.Error("Ephemeral should be true")
	}
	if len(srv.AdvertiseTags) != 1 || srv.AdvertiseTags[0] != "tag:server" {
		t.Errorf("AdvertiseTags = %v", srv.AdvertiseTags)
	}
	if srv.ClientSecret != "tskey-client-abc" {
		t.Errorf("ClientSecret = %q", srv.ClientSecret)
	}
	if srv.ClientID != "client-123" {
		t.Errorf("ClientID = %q", srv.ClientID)
	}
	if srv.IDToken != "eyJ..." {
		t.Errorf("IDToken = %q", srv.IDToken)
	}
	if srv.Audience != "https://login.tailscale.com" {
		t.Errorf("Audience = %q", srv.Audience)
	}
}

func TestApply_EmptyLeavesDefaults(t *testing.T) {
	c := &TailscaleConfig{}
	srv := &tsnet.Server{
		Hostname: "original",
		Dir:      "/original",
	}
	c.Apply(srv)

	if srv.Hostname != "original" {
		t.Errorf("Hostname changed to %q", srv.Hostname)
	}
	if srv.Dir != "/original" {
		t.Errorf("Dir changed to %q", srv.Dir)
	}
	if srv.AuthKey != "" {
		t.Errorf("AuthKey = %q, want empty", srv.AuthKey)
	}
	if srv.Ephemeral {
		t.Error("Ephemeral should remain false")
	}
}
