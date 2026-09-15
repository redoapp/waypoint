package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/delegation"
)

// DelegationAuthorizer authenticates a gateway transport peer using the
// dedicated delegation capability.
type DelegationAuthorizer interface {
	AuthorizeDelegation(ctx context.Context, remoteAddr, backend string) (*auth.TransportIdentity, error)
}

// DelegatedPostgresAuthenticator authenticates the gateway transport, reads
// one preface, verifies and consumes its credential, and returns the agent's
// session.
type DelegatedPostgresAuthenticator struct {
	GatewayAuth       DelegationAuthorizer
	Verifier          *delegation.Verifier
	PrefaceTimeout    time.Duration
	MaxCredentialSize int
}

func (a *DelegatedPostgresAuthenticator) Authenticate(ctx context.Context, conn net.Conn, backend string) (*auth.AuthorizedSession, error) {
	transport, err := a.GatewayAuth.AuthorizeDelegation(ctx, conn.RemoteAddr().String(), backend)
	if err != nil {
		return nil, fmt.Errorf("%w: authorize delegation gateway: %v", ErrCloseWithoutResponse, err)
	}
	credential, err := delegation.ReadPreface(conn, a.PrefaceTimeout, a.MaxCredentialSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCloseWithoutResponse, err)
	}
	session, err := a.Verifier.Verify(ctx, credential, backend, *transport)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCloseWithoutResponse, err)
	}
	return session, nil
}

func (a *DelegatedPostgresAuthenticator) Revalidate(ctx context.Context, _ net.Conn, session *auth.AuthorizedSession, backend string) (*auth.AuthorizedSession, error) {
	if session == nil {
		return nil, errors.New("invalid delegated session")
	}
	delegationContext, delegated := session.Delegation()
	if !delegated || delegationContext.Backend != backend {
		return nil, errors.New("invalid delegated session")
	}
	if _, err := a.GatewayAuth.AuthorizeDelegation(ctx, session.Transport().RemoteAddr, backend); err != nil {
		return nil, err
	}
	return session, nil
}
