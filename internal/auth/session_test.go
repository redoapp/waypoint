package auth

import (
	"testing"
	"time"
)

func TestNewDirectSessionNormalizesIdentity(t *testing.T) {
	authorization := &AuthResult{LoginName: "user@example.com", NodeName: "laptop"}
	session, err := NewDirectSession(authorization, "100.64.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	if session.Authorization() != authorization || session.Principal() != authorization.LoginName || session.QuotaIdentity() != authorization.LoginName {
		t.Fatalf("unexpected direct session identity")
	}
	if session.Provisioning() != (ProvisioningIdentity{LoginName: authorization.LoginName, NodeName: authorization.NodeName}) {
		t.Fatalf("unexpected provisioning identity: %+v", session.Provisioning())
	}
	if _, delegated := session.Delegation(); delegated {
		t.Fatal("direct session has delegation context")
	}
	if !session.Deadline().IsZero() {
		t.Fatalf("direct session has deadline %s", session.Deadline())
	}
}

func TestNewDelegatedSessionEncapsulatesContextAndDeadline(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	session, err := NewDelegatedSession(DelegatedSessionParams{
		Authorization: &AuthResult{Limits: MergedLimits{
			MaxConnDuration: time.Minute,
			Endpoint:        &EndpointLimits{MaxConnDuration: 30 * time.Second},
		}},
		Principal:     "agent:123",
		QuotaIdentity: "quota:123",
		Provisioning: ProvisioningIdentity{
			LoginName: "role:123",
			NodeName:  "agent",
			RoleScope: "scope:readonly",
		},
		Transport: TransportIdentity{
			LoginName:  "gateway@example.com",
			NodeName:   "gateway",
			RemoteAddr: "100.64.0.2:1234",
		},
		CredentialExpiresAt: expiresAt,
		Backend:             "pg-masked",
		Profile:             "readonly",
	})
	if err != nil {
		t.Fatal(err)
	}
	delegation, delegated := session.Delegation()
	if !delegated || delegation.Backend != "pg-masked" || delegation.Profile != "readonly" {
		t.Fatalf("unexpected delegation context: %+v", delegation)
	}
	remaining := time.Until(session.Deadline())
	if remaining <= 0 || remaining > 30*time.Second {
		t.Fatalf("deadline did not apply the shorter endpoint limit: %s", remaining)
	}
}

func TestNewDelegatedSessionRejectsIncompleteVariant(t *testing.T) {
	if _, err := NewDelegatedSession(DelegatedSessionParams{}); err == nil {
		t.Fatal("incomplete delegated session was accepted")
	}
}
