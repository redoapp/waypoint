package delegation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/redoapp/waypoint/internal/auth"
)

type memoryReplayStore struct {
	mu   sync.Mutex
	used map[string]bool
}

func (s *memoryReplayStore) ConsumeDelegationJTI(_ context.Context, issuer, jti string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := issuer + "\x00" + jti
	if s.used[key] {
		return false, nil
	}
	s.used[key] = true
	return true, nil
}

func testKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func testVerifier(t *testing.T, now time.Time, replay ReplayStore) (*Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	key, publicKey := testKey(t)
	v, err := NewVerifier(Config{
		Issuer:   "https://gateway.test",
		Audience: "waypoint.test",
		Keys:     map[string]string{"test-key": publicKey},
		Profiles: map[string]Profile{
			"pgmask-readonly": {
				Backend: "pg-masked",
				Postgres: &auth.PGCap{Databases: map[string]auth.DBPermissions{
					"redo": {Permissions: []string{"readonly"}},
				}},
				Limits: &auth.LimitsCap{MaxConns: 2, MaxConnDuration: "30m"},
			},
		},
	}, replay)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return now }
	return v, key
}

func signCredential(t *testing.T, key any, method jwt.SigningMethod, now time.Time, mutate func(*claims)) string {
	t.Helper()
	c := claims{
		Backend: "pg-masked",
		Profile: "pgmask-readonly",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://gateway.test",
			Audience:  jwt.ClaimStrings{"waypoint.test"},
			Subject:   "coder-agent:agent-123",
			ID:        "credential-123456",
			IssuedAt:  jwt.NewNumericDate(now.Add(-time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Minute)),
		},
	}
	if mutate != nil {
		mutate(&c)
	}
	token := jwt.NewWithClaims(method, c)
	token.Header["kid"] = "test-key"
	token.Header["typ"] = TokenType
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifierResolvesStableDelegatedSessionAndRejectsReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	replay := &memoryReplayStore{used: make(map[string]bool)}
	firstVerifier, key := testVerifier(t, now, replay)
	secondVerifier, _ := testVerifier(t, now, replay)
	secondVerifier.keys["test-key"] = firstVerifier.keys["test-key"]
	raw := signCredential(t, key, jwt.SigningMethodES256, now, nil)

	session, err := firstVerifier.Verify(context.Background(), raw, "pg-masked", auth.TransportIdentity{
		LoginName: "gateway@redo.com", NodeName: "gateway-1", RemoteAddr: "100.64.0.1:1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, delegated := session.Delegation(); !delegated || session.Principal() != "coder-agent:agent-123" {
		t.Fatalf("unexpected session: %+v", session)
	}
	if session.QuotaIdentity() == session.Principal() || session.Transport().LoginName != "gateway@redo.com" {
		t.Fatalf("identities were not separated: %+v", session)
	}
	if auth.DatabasePermissions(session.Authorization(), "pg-masked", "redo") == nil {
		t.Fatal("profile did not resolve redo database permissions")
	}
	if _, err := secondVerifier.Verify(context.Background(), raw, "pg-masked", auth.TransportIdentity{}); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("replay error = %v", err)
	}
}

func TestVerifierSharesBucketsAcrossGatewayInstancesAndSeparatesAgents(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v, key := testVerifier(t, now, &memoryReplayStore{used: make(map[string]bool)})
	firstRaw := signCredential(t, key, jwt.SigningMethodES256, now, nil)
	secondRaw := signCredential(t, key, jwt.SigningMethodES256, now, func(c *claims) {
		c.ID = "credential-654321"
	})
	otherAgentRaw := signCredential(t, key, jwt.SigningMethodES256, now, func(c *claims) {
		c.ID = "credential-abcdef"
		c.Subject = "coder-agent:agent-456"
	})
	first, err := v.Verify(context.Background(), firstRaw, "pg-masked", auth.TransportIdentity{LoginName: "gateway@redo.com", NodeName: "gateway-1", RemoteAddr: "100.64.0.1:1234"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := v.Verify(context.Background(), secondRaw, "pg-masked", auth.TransportIdentity{LoginName: "gateway@redo.com", NodeName: "gateway-2", RemoteAddr: "100.64.0.2:1234"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := v.Verify(context.Background(), otherAgentRaw, "pg-masked", auth.TransportIdentity{LoginName: "gateway@redo.com", NodeName: "gateway-1", RemoteAddr: "100.64.0.1:1234"})
	if err != nil {
		t.Fatal(err)
	}
	if first.QuotaIdentity() != second.QuotaIdentity() || first.Provisioning() != second.Provisioning() {
		t.Fatal("one agent did not retain stable quota and role identities across gateways")
	}
	if first.QuotaIdentity() == other.QuotaIdentity() || first.Provisioning() == other.Provisioning() {
		t.Fatal("different agents shared quota or provisioning identities")
	}
}

func TestVerifierRejectsInvalidCredentials(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name   string
		mutate func(*claims)
		want   string
	}{
		{name: "wrong issuer", mutate: func(c *claims) { c.Issuer = "https://other.test" }, want: "issuer"},
		{name: "wrong audience", mutate: func(c *claims) { c.Audience = jwt.ClaimStrings{"other"} }, want: "audience"},
		{name: "missing subject", mutate: func(c *claims) { c.Subject = "" }, want: "required claims"},
		{name: "missing issued at", mutate: func(c *claims) { c.IssuedAt = nil }, want: "required claims"},
		{name: "missing credential id", mutate: func(c *claims) { c.ID = "" }, want: "required claims"},
		{name: "missing backend", mutate: func(c *claims) { c.Backend = "" }, want: "required claims"},
		{name: "missing profile", mutate: func(c *claims) { c.Profile = "" }, want: "required claims"},
		{name: "expired", mutate: func(c *claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute)) }, want: "expired"},
		{name: "stale issuance", mutate: func(c *claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(-time.Minute - 6*time.Second)) }, want: "previous 60 seconds"},
		{name: "overlong lifetime", mutate: func(c *claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(2 * time.Hour)) }, want: "at most one hour"},
		{name: "wrong backend", mutate: func(c *claims) { c.Backend = "unmasked" }, want: "not valid for listener"},
		{name: "unknown profile", mutate: func(c *claims) { c.Profile = "admin" }, want: "not authorized"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, key := testVerifier(t, now, &memoryReplayStore{used: make(map[string]bool)})
			raw := signCredential(t, key, jwt.SigningMethodES256, now, tt.mutate)
			_, err := v.Verify(context.Background(), raw, "pg-masked", auth.TransportIdentity{})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.want)) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestVerifierRejectsWrongKeyAlgorithmAndTampering(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v, key := testVerifier(t, now, &memoryReplayStore{used: make(map[string]bool)})
	other, _ := testKey(t)

	wrongKey := signCredential(t, other, jwt.SigningMethodES256, now, nil)
	if _, err := v.Verify(context.Background(), wrongKey, "pg-masked", auth.TransportIdentity{}); err == nil {
		t.Fatal("wrong signing key was accepted")
	}

	hmac := signCredential(t, []byte("not-an-ecdsa-key"), jwt.SigningMethodHS256, now, nil)
	if _, err := v.Verify(context.Background(), hmac, "pg-masked", auth.TransportIdentity{}); err == nil {
		t.Fatal("wrong algorithm was accepted")
	}

	tampered := signCredential(t, key, jwt.SigningMethodES256, now, nil)
	tampered = tampered[:len(tampered)-1] + "A"
	if _, err := v.Verify(context.Background(), tampered, "pg-masked", auth.TransportIdentity{}); err == nil {
		t.Fatal("tampered credential was accepted")
	}
}

func TestVerifierRejectsWrongTypeAndUnknownKeyID(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v, key := testVerifier(t, now, &memoryReplayStore{used: make(map[string]bool)})

	for _, tc := range []struct {
		name  string
		type_ string
		kid   string
	}{
		{name: "wrong type", type_: "JWT", kid: "test-key"},
		{name: "unknown key", type_: TokenType, kid: "retired-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := claims{
				Backend: "pg-masked",
				Profile: "pgmask-readonly",
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "https://gateway.test",
					Audience:  jwt.ClaimStrings{"waypoint.test"},
					Subject:   "coder-agent:agent-123",
					ID:        "credential-headers-" + tc.name,
					IssuedAt:  jwt.NewNumericDate(now.Add(-time.Second)),
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodES256, c)
			token.Header["kid"] = tc.kid
			token.Header["typ"] = tc.type_
			raw, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.Verify(context.Background(), raw, "pg-masked", auth.TransportIdentity{}); err == nil {
				t.Fatal("credential with invalid protected header was accepted")
			}
		})
	}
}
