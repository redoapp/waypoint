package restrict

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
)

// ErrByteLimitExceeded is returned when the per-connection byte limit is exceeded.
var ErrByteLimitExceeded = errors.New("per-connection byte limit exceeded")

// ErrBandwidthLimitExceeded is returned when a bandwidth tier limit is exceeded.
var ErrBandwidthLimitExceeded = errors.New("bandwidth limit exceeded")

// ErrDeadlineExceeded is returned when the connection duration limit is exceeded.
var ErrDeadlineExceeded = errors.New("connection duration limit exceeded")

// Direction indicates which side of the relay initiated the close.
type Direction string

const (
	DirClient  Direction = "client"
	DirBackend Direction = "backend"
)

// CloseReason categorizes why a relay ended.
type CloseReason string

const (
	CloseNormal  CloseReason = "normal"  // clean EOF from one side
	CloseLimit   CloseReason = "limit"   // byte, bandwidth, or duration limit exceeded
	CloseNetwork CloseReason = "network" // I/O error (not EOF)
)

// RelayResult describes how a bidirectional relay ended.
type RelayResult struct {
	Reason      CloseReason
	InitiatedBy Direction
	Err         error // underlying error; nil for clean EOF
}

// ConnLimits tracks per-connection limits and batches byte updates to Redis.
type ConnLimits struct {
	store           *RedisStore
	metrics         *metrics.Metrics
	user            string
	scope           string // listener name for hierarchical key scoping
	maxBytesPerConn int64
	bandwidthTiers  []auth.BandwidthTier
	deadline        time.Time
	logger          *slog.Logger
	flushInterval   time.Duration

	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
	pendingBytes atomic.Int64 // unflushed bytes to report to Redis
	totalBytes   atomic.Int64 // monotonic total for per-connection limit

	// Per-direction pending bytes for OTel reporting.
	pendingRead    atomic.Int64
	pendingWritten atomic.Int64
	listenerAttr   attribute.KeyValue // listener tag for OTel byte metrics

	closeOnce sync.Once
	done      chan struct{}
	limitErr  error
	mu        sync.Mutex
}

// SetFlushIntervalForTest overrides the flush interval. Must be called before Start.
func (cl *ConnLimits) SetFlushIntervalForTest(d time.Duration) {
	cl.flushInterval = d
}

// Start begins the background flush goroutine. Call Stop when done.
func (cl *ConnLimits) Start() {
	cl.done = make(chan struct{})
	go cl.flushLoop()
}

// Stop flushes remaining bytes and stops the background goroutine.
func (cl *ConnLimits) Stop() {
	cl.closeOnce.Do(func() {
		close(cl.done)
		cl.flush() // final flush
	})
}

// BytesRead returns the total bytes read from the client side.
func (cl *ConnLimits) BytesRead() int64 {
	return cl.bytesRead.Load()
}

// BytesWritten returns the total bytes written to the client side.
func (cl *ConnLimits) BytesWritten() int64 {
	return cl.bytesWritten.Load()
}

// ReportBytes records bytes transferred and checks per-connection limits.
// Returns an error if a limit is exceeded.
func (cl *ConnLimits) ReportBytes(n int64) error {
	cl.pendingBytes.Add(n)
	cl.totalBytes.Add(n)

	if cl.maxBytesPerConn > 0 {
		total := cl.totalBytes.Load()
		if total > cl.maxBytesPerConn {
			if cl.metrics != nil {
				cl.metrics.LimitViolations.Add(context.Background(), 1,
					cl.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("bytes_per_conn")))
			}
			return ErrByteLimitExceeded
		}
	}

	if !cl.deadline.IsZero() && time.Now().After(cl.deadline) {
		if cl.metrics != nil {
			cl.metrics.LimitViolations.Add(context.Background(), 1,
				cl.metrics.Attrs("waypoint.limit.violations", metrics.AttrLimitType.String("conn_duration")))
		}
		return ErrDeadlineExceeded
	}

	return cl.checkLimitErr()
}

// ReportRead records bytes read from the client side.
func (cl *ConnLimits) ReportRead(n int64) error {
	cl.bytesRead.Add(n)
	cl.pendingRead.Add(n)
	return cl.ReportBytes(n)
}

// ReportWrite records bytes written to the client side.
func (cl *ConnLimits) ReportWrite(n int64) error {
	cl.bytesWritten.Add(n)
	cl.pendingWritten.Add(n)
	return cl.ReportBytes(n)
}

func (cl *ConnLimits) checkLimitErr() error {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.limitErr
}

func (cl *ConnLimits) setLimitErr(err error) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.limitErr == nil {
		cl.limitErr = err
	}
}

func (cl *ConnLimits) flushLoop() {
	ticker := time.NewTicker(cl.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cl.done:
			return
		case <-ticker.C:
			cl.flush()
		}
	}
}

func (cl *ConnLimits) flush() {
	// Flush aggregate bytes to Redis.
	if pending := cl.pendingBytes.Swap(0); pending > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cl.store.AddBytes(ctx, cl.user, cl.scope, pending)

		// Check bandwidth limits across all tiers.
		if len(cl.bandwidthTiers) > 0 {
			result, err := cl.store.AddBandwidthBytesMulti(ctx, cl.user, cl.scope, pending, cl.bandwidthTiers)
			if err != nil {
				cl.logger.Error("bandwidth flush failed", "user", cl.user, "error", err)
			} else if result.Exceeded {
				cl.setLimitErr(ErrBandwidthLimitExceeded)
			}
		}
	}

	// Report per-direction byte deltas to OTel — always report (even 0) so
	// Datadog can distinguish "no traffic" from "no data".
	if cl.metrics != nil {
		ctx := context.Background()
		pr := cl.pendingRead.Swap(0)
		pw := cl.pendingWritten.Swap(0)
		cl.metrics.BytesRead.Add(ctx, pr,
			cl.metrics.Attrs("waypoint.bytes.read", cl.listenerAttr, metrics.AttrUser.String(cl.user)))
		cl.metrics.BytesWritten.Add(ctx, pw,
			cl.metrics.Attrs("waypoint.bytes.written", cl.listenerAttr, metrics.AttrUser.String(cl.user)))
	}
}

// relayEvent pairs a copy result with the direction it came from.
type relayEvent struct {
	dir Direction
	err error
}

// Relay copies data bidirectionally between client and backend,
// enforcing limits via the ConnLimits tracker.
func Relay(client, backend net.Conn, cl *ConnLimits) RelayResult {
	cl.Start()
	defer cl.Stop()

	errc := make(chan relayEvent, 2)

	// client → backend (reading from client side).
	go func() {
		errc <- relayEvent{dir: DirClient, err: copyWithLimits(backend, client, cl.ReportRead)}
	}()
	// backend → client (reading from backend side).
	go func() {
		errc <- relayEvent{dir: DirBackend, err: copyWithLimits(client, backend, cl.ReportWrite)}
	}()

	// Wait for first error (one direction closed).
	first := <-errc

	// Close both sides to unblock the other goroutine.
	client.Close()
	backend.Close()

	// Wait for second goroutine.
	<-errc

	return classifyResult(first)
}

func classifyResult(first relayEvent) RelayResult {
	r := RelayResult{
		InitiatedBy: first.dir,
		Err:         first.err,
	}
	switch {
	case first.err == nil:
		r.Reason = CloseNormal
	case errors.Is(first.err, ErrByteLimitExceeded),
		errors.Is(first.err, ErrBandwidthLimitExceeded),
		errors.Is(first.err, ErrDeadlineExceeded):
		r.Reason = CloseLimit
	default:
		r.Reason = CloseNetwork
	}
	return r
}

func copyWithLimits(dst, src net.Conn, report func(int64) error) error {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if err := report(int64(n)); err != nil {
				return err
			}
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}
