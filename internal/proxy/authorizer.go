package proxy

import (
	"context"

	"github.com/redoapp/waypoint/internal/auth"
	"tailscale.com/client/local"
)

// Authorizer abstracts the identity check so that tests can supply a mock
// while production wiring uses the real Tailscale local client.
type Authorizer interface {
	Authorize(ctx context.Context, remoteAddr string, backend string) (*auth.AuthResult, error)
}

// TailscaleAuthorizer implements Authorizer using the Tailscale local API.
type TailscaleAuthorizer struct {
	LC *local.Client
}

// Authorize delegates to auth.Authorize with the embedded local client.
func (a *TailscaleAuthorizer) Authorize(ctx context.Context, remoteAddr string, backend string) (*auth.AuthResult, error) {
	return auth.Authorize(ctx, a.LC, remoteAddr, backend)
}
