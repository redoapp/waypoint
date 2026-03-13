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
)

var errByteLimitExceeded = errors.New("per-connection byte limit exceeded")
var errBandwidthLimitExceeded = errors.New("bandwidth limit exceeded")
var errDeadlineExceeded = errors.New("connection duration limit exceeded")

// ConnLimits tracks per-connection limits and batches byte updates to Redis.
type ConnLimits struct {
	store           *RedisStore
	user            string
	maxBytesPerConn int64
	bandwidthBytes  int64
	bandwidthPeriod time.Duration
	deadline        time.Time
	logger          *slog.Logger
	flushInterval   time.Duration

	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
	pendingBytes atomic.Int64 // unflushed bytes to report to Redis
	totalBytes   atomic.Int64 // monotonic total for per-connection limit

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

// ReportBytes records bytes transferred and checks per-connection limits.
// Returns an error if a limit is exceeded.
func (cl *ConnLimits) ReportBytes(n int64) error {
	cl.pendingBytes.Add(n)
	cl.totalBytes.Add(n)

	if cl.maxBytesPerConn > 0 {
		total := cl.totalBytes.Load()
		if total > cl.maxBytesPerConn {
			return errByteLimitExceeded
		}
	}

	if !cl.deadline.IsZero() && time.Now().After(cl.deadline) {
		return errDeadlineExceeded
	}

	return cl.checkLimitErr()
}

// ReportRead records bytes read from the client side.
func (cl *ConnLimits) ReportRead(n int64) error {
	cl.bytesRead.Add(n)
	return cl.ReportBytes(n)
}

// ReportWrite records bytes written to the client side.
func (cl *ConnLimits) ReportWrite(n int64) error {
	cl.bytesWritten.Add(n)
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
	pending := cl.pendingBytes.Swap(0)
	if pending == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Update aggregate bytes.
	cl.store.AddBytes(ctx, cl.user, pending)

	// Check bandwidth limit.
	if cl.bandwidthBytes > 0 && cl.bandwidthPeriod > 0 {
		total, err := cl.store.AddBandwidthBytes(ctx, cl.user, pending, cl.bandwidthPeriod)
		if err != nil {
			cl.logger.Error("bandwidth flush failed", "user", cl.user, "error", err)
			return
		}
		if total > cl.bandwidthBytes {
			cl.setLimitErr(errBandwidthLimitExceeded)
		}
	}
}

// Relay copies data bidirectionally between client and backend,
// enforcing limits via the ConnLimits tracker.
func Relay(client, backend net.Conn, cl *ConnLimits) error {
	cl.Start()
	defer cl.Stop()

	errc := make(chan error, 2)

	go func() {
		errc <- copyWithLimits(backend, client, cl.ReportRead)
	}()
	go func() {
		errc <- copyWithLimits(client, backend, cl.ReportWrite)
	}()

	// Wait for first error (one direction closed).
	err := <-errc

	// Close both sides to unblock the other goroutine.
	client.Close()
	backend.Close()

	// Wait for second goroutine.
	<-errc

	return err
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
