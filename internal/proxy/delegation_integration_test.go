//go:build integration

package proxy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/delegation"
	"github.com/redoapp/waypoint/internal/proxy"
)

type integrationReplayStore struct {
	mu   sync.Mutex
	used map[string]struct{}
}

func (s *integrationReplayStore) ConsumeDelegationJTI(_ context.Context, issuer, jti string, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := issuer + "\x00" + jti
	if _, ok := s.used[key]; ok {
		return false, nil
	}
	s.used[key] = struct{}{}
	return true, nil
}

type integrationGatewayAuthorizer struct {
	revoked atomic.Bool
	checks  atomic.Int32
}

func (a *integrationGatewayAuthorizer) AuthorizeDelegation(_ context.Context, remoteAddr, _ string) (*auth.TransportIdentity, error) {
	a.checks.Add(1)
	if a.revoked.Load() {
		return nil, errors.New("delegation capability revoked")
	}
	return &auth.TransportIdentity{
		LoginName:  "gateway@redo.com",
		NodeName:   "gateway-replica",
		RemoteAddr: remoteAddr,
	}, nil
}

type delegatedIntegrationFixture struct {
	address    string
	privateKey *ecdsa.PrivateKey
	gateway    *integrationGatewayAuthorizer
	jti        atomic.Int64
}

func setupDelegatedProxy(t *testing.T, maxConns int, revalidation time.Duration) delegatedIntegrationFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	verifier, err := delegation.NewVerifier(delegation.Config{
		Issuer:   "https://gateway.test",
		Audience: "waypoint.test",
		Keys:     map[string]string{"integration": string(publicKey)},
		Profiles: map[string]delegation.Profile{
			"pgmask-readonly": {
				Backend: "test-listener",
				Postgres: &auth.PGCap{Databases: map[string]auth.DBPermissions{
					"waypoint_test": {Permissions: []string{"readonly"}},
				}},
				Limits: &auth.LimitsCap{MaxConns: maxConns},
			},
			"alternate-readonly": {
				Backend: "test-listener",
				Postgres: &auth.PGCap{Databases: map[string]auth.DBPermissions{
					"waypoint_test": {Permissions: []string{"readonly"}},
				}},
				Limits: &auth.LimitsCap{MaxConns: maxConns},
			},
		},
	}, &integrationReplayStore{used: make(map[string]struct{})})
	if err != nil {
		t.Fatal(err)
	}
	gateway := &integrationGatewayAuthorizer{}
	address := setupProxyWithAuth(t, &mockAuthorizer{}, func(p *proxy.PostgresProxy) {
		p.SessionAuth = &proxy.DelegatedPostgresAuthenticator{
			GatewayAuth:       gateway,
			Verifier:          verifier,
			PrefaceTimeout:    time.Second,
			MaxCredentialSize: delegation.DefaultMaxCredentialSize,
		}
		p.RevalInterval = revalidation
	})
	t.Cleanup(func() { cleanupRole(t, "delegated-role", "agent", "waypoint_test") })
	return delegatedIntegrationFixture{address: address, privateKey: key, gateway: gateway}
}

func (f *delegatedIntegrationFixture) credential(t *testing.T, subject, profile, backend string, lifetime time.Duration) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	claims := jwt.MapClaims{
		"iss":     "https://gateway.test",
		"aud":     "waypoint.test",
		"sub":     subject,
		"iat":     now.Unix(),
		"exp":     now.Add(lifetime).Unix(),
		"jti":     fmt.Sprintf("integration-%d", f.jti.Add(1)),
		"backend": backend,
		"profile": profile,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "integration"
	token.Header["typ"] = delegation.TokenType
	raw, err := token.SignedString(f.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func delegatedConnect(t *testing.T, address, database, credential string) (*pgx.Conn, error) {
	t.Helper()
	config, err := pgx.ParseConfig(fmt.Sprintf("postgres://ignored:ignored@%s/%s?sslmode=disable", address, database))
	if err != nil {
		return nil, err
	}
	config.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if err := delegation.WritePreface(conn, credential); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgx.ConnectConfig(ctx, config)
}

func TestIntegration_DelegatedPostgresPermissionsQuotasAndRoleScope(t *testing.T) {
	fixture := setupDelegatedProxy(t, 1, 0)
	first, err := delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:one", "pgmask-readonly", "test-listener", 5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())

	var firstRole string
	if err := first.QueryRow(context.Background(), "SELECT current_user").Scan(&firstRole); err != nil {
		t.Fatalf("masked read: %v", err)
	}
	if _, err := first.Exec(context.Background(), "CREATE TABLE delegated_write_denied (id int)"); err == nil {
		t.Fatal("delegated readonly session accepted a write")
	}

	_, err = delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:one", "pgmask-readonly", "test-listener", 5*time.Minute))
	if err == nil {
		t.Fatal("second connection for one agent bypassed the shared quota")
	}

	otherAgent, err := delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:two", "pgmask-readonly", "test-listener", 5*time.Minute))
	if err != nil {
		t.Fatalf("separate agent did not receive a separate quota: %v", err)
	}
	defer otherAgent.Close(context.Background())

	first.Close(context.Background())
	alternate, err := delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:one", "alternate-readonly", "test-listener", 5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer alternate.Close(context.Background())
	var alternateRole string
	if err := alternate.QueryRow(context.Background(), "SELECT current_user").Scan(&alternateRole); err != nil {
		t.Fatal(err)
	}
	if firstRole == alternateRole {
		t.Fatal("different profiles reused one provisioned role")
	}

	if _, err := delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:three", "admin", "test-listener", 5*time.Minute)); err == nil {
		t.Fatal("unconfigured profile escalation succeeded")
	}
	if _, err := delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:three", "pgmask-readonly", "other-listener", 5*time.Minute)); err == nil {
		t.Fatal("backend escalation succeeded")
	}
}

func TestIntegration_DelegatedPostgresExpiresWhileIdle(t *testing.T) {
	fixture := setupDelegatedProxy(t, 2, 0)
	conn, err := delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:expiry", "pgmask-readonly", "test-listener", 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	time.Sleep(3 * time.Second)
	var one int
	if err := conn.QueryRow(context.Background(), "SELECT 1").Scan(&one); err == nil {
		t.Fatal("idle delegated connection survived credential expiration")
	}
}

func TestIntegration_DelegatedPostgresExpiresDuringActiveQuery(t *testing.T) {
	fixture := setupDelegatedProxy(t, 2, 0)
	conn, err := delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:active-expiry", "pgmask-readonly", "test-listener", 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	queryCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := conn.QueryRow(queryCtx, "SELECT pg_sleep(30)").Scan(new(any)); err == nil {
		t.Fatal("active delegated query survived credential expiration")
	}
}

func TestIntegration_DelegatedPostgresClosesWhenGatewayCapabilityIsRevoked(t *testing.T) {
	fixture := setupDelegatedProxy(t, 2, 100*time.Millisecond)
	conn, err := delegatedConnect(t, fixture.address, "waypoint_test", fixture.credential(t, "agent:revoked", "pgmask-readonly", "test-listener", 5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	fixture.gateway.revoked.Store(true)
	time.Sleep(300 * time.Millisecond)
	var one int
	if err := conn.QueryRow(context.Background(), "SELECT 1").Scan(&one); err == nil {
		t.Fatal("delegated connection survived gateway capability revocation")
	}
	if fixture.gateway.checks.Load() < 2 {
		t.Fatal("delegation capability was not revalidated")
	}
}
