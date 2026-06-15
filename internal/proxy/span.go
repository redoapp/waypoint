package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"syscall"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/redoapp/waypoint/internal/metrics"
)

// isBenignDisconnect reports whether err represents an expected client-side
// disconnect during connection setup rather than a real proxy or backend fault.
//
// MongoDB drivers routinely open monitoring/pool-probe connections that send a
// hello and then close the socket before (or partway through) authenticating;
// Postgres clients similarly drop before completing startup. These surface as
// EOF or connection-reset and must NOT be recorded as error spans — left
// unclassified they dominate error-span volume and bury genuine failures.
func isBenignDisconnect(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET)
}

// recordSetupFailure ends the waypoint.connection.setup span for a failed
// handshake, classifying benign client disconnects so they are reported as a
// low-severity outcome (counter + debug log) instead of an error span. For
// genuine failures it records the error, sets error status, and logs at error
// level — matching the previous inline behavior. The span is ended here; the
// caller must not end it again and remains responsible for any client-facing
// error reply.
func recordSetupFailure(ctx context.Context, log *slog.Logger, m *metrics.Metrics, span trace.Span, err error, reason, logMsg, listener, mode string) {
	if isBenignDisconnect(err) {
		span.SetAttributes(attribute.String("waypoint.setup_outcome", "client_disconnect"))
		span.End()
		m.HandshakeAborted.Add(ctx, 1, m.Attrs("waypoint.handshake.aborted",
			metrics.AttrListener.String(listener), metrics.AttrMode.String(mode)))
		log.DebugContext(ctx, "client disconnected during handshake", "error", err, "stage", reason)
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, reason)
	span.End()
	log.ErrorContext(ctx, logMsg, "error", err)
}
