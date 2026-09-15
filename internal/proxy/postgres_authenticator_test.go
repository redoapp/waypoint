package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
)

func testDelegatedSession(t *testing.T, expiresAt time.Time, limits auth.MergedLimits) *auth.AuthorizedSession {
	t.Helper()
	session, err := auth.NewDelegatedSession(auth.DelegatedSessionParams{
		Authorization: &auth.AuthResult{Limits: limits},
		Principal:     "agent:test",
		QuotaIdentity: "quota:test",
		Provisioning: auth.ProvisioningIdentity{
			LoginName: "role:test",
			NodeName:  "agent",
			RoleScope: "scope:test",
		},
		Transport: auth.TransportIdentity{
			LoginName:  "gateway@test",
			NodeName:   "gateway",
			RemoteAddr: "100.64.0.1:1234",
		},
		CredentialExpiresAt: expiresAt,
		Backend:             "test-listener",
		Profile:             "readonly",
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestSessionContextUsesCredentialExpiration(t *testing.T) {
	expiresAt := time.Now().Add(50 * time.Millisecond)
	session := testDelegatedSession(t, expiresAt, auth.MergedLimits{})
	ctx, cancel := sessionContext(context.Background(), session.Deadline())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.Equal(expiresAt) {
		t.Fatalf("deadline = %v, %v; want %v", deadline, ok, expiresAt)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("session did not expire")
	}
}

func TestSessionContextAppliesShorterConnectionLimit(t *testing.T) {
	session := testDelegatedSession(t, time.Now().Add(time.Hour), auth.MergedLimits{
		MaxConnDuration: time.Minute,
		Endpoint:        &auth.EndpointLimits{MaxConnDuration: 10 * time.Millisecond},
	})
	ctx, cancel := sessionContext(context.Background(), session.Deadline())
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 100*time.Millisecond {
		t.Fatalf("shorter endpoint deadline was not applied: %v", deadline)
	}
}

func TestSessionContextPreservesDirectLimiterSemantics(t *testing.T) {
	session, err := auth.NewDirectSession(&auth.AuthResult{
		LoginName: "user@test",
		NodeName:  "node",
		Limits:    auth.MergedLimits{MaxConnDuration: time.Millisecond},
	}, "100.64.0.2:1234")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := sessionContext(context.Background(), session.Deadline())
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("direct session duration moved from the existing relay limiter")
	}
}
