package proxy

import (
	"context"
	"errors"
	"net"

	"github.com/redoapp/waypoint/internal/auth"
)

// ErrCloseWithoutResponse marks admission failures that occur before the
// PostgreSQL stream begins. The caller must close without writing PG bytes.
var ErrCloseWithoutResponse = errors.New("close connection without response")

// PostgresAuthenticator resolves either a direct Tailscale connection or a
// delegated preface to the common authorized session representation.
type PostgresAuthenticator interface {
	Authenticate(ctx context.Context, conn net.Conn, backend string) (*auth.AuthorizedSession, error)
	Revalidate(ctx context.Context, conn net.Conn, session *auth.AuthorizedSession, backend string) (*auth.AuthorizedSession, error)
}

type directPostgresAuthenticator struct {
	authorizer Authorizer
}

func (a directPostgresAuthenticator) Authenticate(ctx context.Context, conn net.Conn, backend string) (*auth.AuthorizedSession, error) {
	result, err := a.authorizer.Authorize(ctx, conn.RemoteAddr().String(), backend)
	if err != nil {
		return nil, err
	}
	return auth.NewDirectSession(result, conn.RemoteAddr().String())
}

func (a directPostgresAuthenticator) Revalidate(ctx context.Context, conn net.Conn, _ *auth.AuthorizedSession, backend string) (*auth.AuthorizedSession, error) {
	return a.Authenticate(ctx, conn, backend)
}
