package auth

import (
	"errors"
	"time"
)

// TransportIdentity identifies the authenticated network peer carrying a
// connection. For delegated sessions this is the gateway, not the principal.
type TransportIdentity struct {
	LoginName  string
	NodeName   string
	RemoteAddr string
}

// ProvisioningIdentity defines the stable inputs used to provision a database
// role independently of the transport peer.
type ProvisioningIdentity struct {
	LoginName string
	NodeName  string
	RoleScope string
}

// DelegationContext contains the metadata that exists only for a delegated
// session. A nil context identifies a direct session.
type DelegationContext struct {
	Backend string
	Profile string
}

// DelegatedSessionParams contains the verified inputs for a delegated session.
type DelegatedSessionParams struct {
	Authorization       *AuthResult
	Principal           string
	QuotaIdentity       string
	Provisioning        ProvisioningIdentity
	Transport           TransportIdentity
	CredentialExpiresAt time.Time
	Backend             string
	Profile             string
}

// AuthorizedSession is the normalized result consumed by the PostgreSQL
// handler after either direct or delegated authentication.
type AuthorizedSession struct {
	authorization *AuthResult
	principal     string
	quotaIdentity string
	provisioning  ProvisioningIdentity
	transport     TransportIdentity
	deadline      time.Time
	delegation    *DelegationContext
}

// NewDirectSession adapts an ordinary Tailscale authorization result to the
// common PostgreSQL session model.
func NewDirectSession(result *AuthResult, remoteAddr string) (*AuthorizedSession, error) {
	if result == nil || result.LoginName == "" || remoteAddr == "" {
		return nil, errors.New("direct session requires an authorized transport identity")
	}
	return &AuthorizedSession{
		authorization: result,
		principal:     result.LoginName,
		quotaIdentity: result.LoginName,
		provisioning: ProvisioningIdentity{
			LoginName: result.LoginName,
			NodeName:  result.NodeName,
		},
		transport: TransportIdentity{
			LoginName:  result.LoginName,
			NodeName:   result.NodeName,
			RemoteAddr: remoteAddr,
		},
	}, nil
}

// NewDelegatedSession constructs a delegated session after credential and
// transport verification.
func NewDelegatedSession(params DelegatedSessionParams) (*AuthorizedSession, error) {
	if params.Authorization == nil || params.Principal == "" || params.QuotaIdentity == "" {
		return nil, errors.New("delegated session requires authorization and stable identities")
	}
	if params.Provisioning.LoginName == "" || params.Provisioning.NodeName == "" || params.Provisioning.RoleScope == "" {
		return nil, errors.New("delegated session requires a scoped provisioning identity")
	}
	if params.Transport.LoginName == "" || params.Transport.RemoteAddr == "" {
		return nil, errors.New("delegated session requires an authorized transport identity")
	}
	if params.CredentialExpiresAt.IsZero() || params.Backend == "" || params.Profile == "" {
		return nil, errors.New("delegated session requires credential metadata")
	}

	deadline := params.CredentialExpiresAt
	if maxDuration := shortestConnectionDuration(params.Authorization.Limits); maxDuration > 0 {
		limitDeadline := time.Now().Add(maxDuration)
		if limitDeadline.Before(deadline) {
			deadline = limitDeadline
		}
	}
	return &AuthorizedSession{
		authorization: params.Authorization,
		principal:     params.Principal,
		quotaIdentity: params.QuotaIdentity,
		provisioning:  params.Provisioning,
		transport:     params.Transport,
		deadline:      deadline,
		delegation: &DelegationContext{
			Backend: params.Backend,
			Profile: params.Profile,
		},
	}, nil
}

func shortestConnectionDuration(limits MergedLimits) time.Duration {
	duration := limits.MaxConnDuration
	if endpoint := limits.Endpoint; endpoint != nil && endpoint.MaxConnDuration > 0 && (duration == 0 || endpoint.MaxConnDuration < duration) {
		duration = endpoint.MaxConnDuration
	}
	return duration
}

func (s *AuthorizedSession) Authorization() *AuthResult {
	return s.authorization
}

func (s *AuthorizedSession) Principal() string {
	return s.principal
}

func (s *AuthorizedSession) QuotaIdentity() string {
	return s.quotaIdentity
}

func (s *AuthorizedSession) Provisioning() ProvisioningIdentity {
	return s.provisioning
}

func (s *AuthorizedSession) Transport() TransportIdentity {
	return s.transport
}

func (s *AuthorizedSession) Deadline() time.Time {
	return s.deadline
}

func (s *AuthorizedSession) Delegation() (DelegationContext, bool) {
	if s.delegation == nil {
		return DelegationContext{}, false
	}
	return *s.delegation, true
}
