package restrict

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
)

func setupConnTest(t *testing.T) *RedisStore {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return NewRedisStore(rdb, "test:", metrics.Noop())
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestConnLimits_BytesReadWritten(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		logger:        testLogger(),
		flushInterval: time.Hour,
		done:          make(chan struct{}),
	}

	cl.ReportRead(100)
	cl.ReportWrite(200)
	cl.ReportRead(50)

	if got := cl.BytesRead(); got != 150 {
		t.Errorf("BytesRead() = %d, want 150", got)
	}
	if got := cl.BytesWritten(); got != 200 {
		t.Errorf("BytesWritten() = %d, want 200", got)
	}
}

func TestConnLimits_ByteLimit(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:           store,
		user:            "alice",
		maxBytesPerConn: 100,
		logger:          testLogger(),
		flushInterval:   time.Hour, // don't flush automatically
		done:            make(chan struct{}),
	}

	// Under limit.
	if err := cl.ReportBytes(50); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Over limit.
	if err := cl.ReportBytes(60); err != errByteLimitExceeded {
		t.Fatalf("expected byte limit exceeded, got: %v", err)
	}
}

func TestConnLimits_ByteLimit_NoPending(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:           store,
		user:            "alice",
		maxBytesPerConn: 100,
		logger:          testLogger(),
		flushInterval:   time.Hour,
		done:            make(chan struct{}),
	}

	// ReportRead tracks bytesRead separately.
	if err := cl.ReportRead(40); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := cl.ReportWrite(40); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Total is 80 read + written; adding 30 via pending pushes over 100.
	if err := cl.ReportBytes(30); err != errByteLimitExceeded {
		t.Fatalf("expected byte limit exceeded, got: %v", err)
	}
}

func TestConnLimits_NoLimit(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		logger:        testLogger(),
		flushInterval: time.Hour,
		done:          make(chan struct{}),
	}

	// Should never error on bytes when no limit set.
	if err := cl.ReportBytes(1_000_000_000); err != nil {
		t.Fatalf("unexpected error with no limit: %v", err)
	}
}

func TestConnLimits_DeadlineExceeded(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		deadline:      time.Now().Add(-time.Second), // already past
		logger:        testLogger(),
		flushInterval: time.Hour,
		done:          make(chan struct{}),
	}

	if err := cl.ReportBytes(0); err != errDeadlineExceeded {
		t.Fatalf("expected deadline exceeded, got: %v", err)
	}
}

func TestConnLimits_FlushWritesToRedis(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		logger:        testLogger(),
		flushInterval: time.Hour,
		done:          make(chan struct{}),
	}

	cl.ReportBytes(500)
	cl.flush()

	ctx := context.Background()
	total, err := store.AddBytes(ctx, "alice", 0) // Just read current.
	if err != nil {
		t.Fatal(err)
	}
	if total != 500 {
		t.Errorf("expected 500 in Redis, got %d", total)
	}

	// Pending should be cleared.
	if cl.pendingBytes.Load() != 0 {
		t.Errorf("expected 0 pending after flush, got %d", cl.pendingBytes.Load())
	}
}

func TestConnLimits_FlushZeroPendingIsNoop(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		logger:        testLogger(),
		flushInterval: time.Hour,
		done:          make(chan struct{}),
	}

	cl.flush() // Should not error or write anything.

	ctx := context.Background()
	total, _ := store.AddBytes(ctx, "alice", 0)
	if total != 0 {
		t.Errorf("expected 0 after no-op flush, got %d", total)
	}
}

func TestConnLimits_BandwidthLimitViaFlush(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:          store,
		user:           "alice",
		bandwidthTiers: []auth.BandwidthTier{{Bytes: 100, Period: time.Hour}},
		logger:         testLogger(),
		flushInterval:  time.Hour,
		done:           make(chan struct{}),
	}

	cl.pendingBytes.Store(150) // Over bandwidth limit.
	cl.flush()

	if err := cl.checkLimitErr(); err != errBandwidthLimitExceeded {
		t.Fatalf("expected bandwidth limit exceeded, got: %v", err)
	}
}

func TestConnLimits_BandwidthMultiTierViaFlush(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store: store,
		user:  "alice",
		bandwidthTiers: []auth.BandwidthTier{
			{Bytes: 10000, Period: time.Hour},     // generous hourly
			{Bytes: 200, Period: 168 * time.Hour}, // tight weekly
		},
		logger:        testLogger(),
		flushInterval: time.Hour,
		done:          make(chan struct{}),
	}

	cl.pendingBytes.Store(300) // Under hourly, over weekly.
	cl.flush()

	if err := cl.checkLimitErr(); err != errBandwidthLimitExceeded {
		t.Fatalf("expected bandwidth limit exceeded (weekly tier), got: %v", err)
	}
}

func TestConnLimits_StartStop(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		logger:        testLogger(),
		flushInterval: 10 * time.Millisecond,
	}

	cl.ReportBytes(100)
	cl.Start()
	time.Sleep(50 * time.Millisecond) // Let flush happen.
	cl.Stop()

	// After stop, pending should be flushed.
	if cl.pendingBytes.Load() != 0 {
		t.Errorf("expected 0 pending after stop, got %d", cl.pendingBytes.Load())
	}
}

func TestConnLimits_StopIdempotent(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		logger:        testLogger(),
		flushInterval: time.Hour,
	}
	cl.Start()
	cl.Stop()
	cl.Stop() // Should not panic.
}

func TestRelay_BasicCopy(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		logger:        testLogger(),
		flushInterval: time.Hour,
	}

	clientConn, clientRemote := net.Pipe()
	backendConn, backendRemote := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- Relay(clientConn, backendConn, cl)
	}()

	// Write from "client side" (clientRemote), read from "backend side" (backendRemote).
	msg := []byte("hello from client")
	go func() {
		clientRemote.Write(msg)
		clientRemote.Close()
	}()

	buf := make([]byte, 100)
	n, _ := backendRemote.Read(buf)
	if string(buf[:n]) != "hello from client" {
		t.Errorf("expected 'hello from client', got %q", string(buf[:n]))
	}
	backendRemote.Close()

	err := <-done
	if err != nil {
		t.Fatalf("relay returned error: %v", err)
	}
}

func TestConnLimits_ByteLimit_ViaReportReadWrite(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:           store,
		user:            "alice",
		maxBytesPerConn: 100,
		logger:          testLogger(),
		flushInterval:   time.Hour,
		done:            make(chan struct{}),
	}

	// Under limit via ReportRead.
	if err := cl.ReportRead(30); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Under limit via ReportWrite.
	if err := cl.ReportWrite(30); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Still under: total = 60.
	if err := cl.ReportRead(30); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Over limit: total = 90 + 20 = 110 > 100.
	if err := cl.ReportWrite(20); err != errByteLimitExceeded {
		t.Fatalf("expected byte limit exceeded, got: %v", err)
	}
}

func TestConnLimits_ReportReadWrite_FlushesToRedis(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:          store,
		user:           "alice",
		bandwidthTiers: []auth.BandwidthTier{{Bytes: 10000, Period: time.Hour}},
		logger:         testLogger(),
		flushInterval:  time.Hour,
		done:           make(chan struct{}),
	}

	// Report bytes via ReportRead/ReportWrite — these must accumulate in pendingBytes.
	cl.ReportRead(200)
	cl.ReportWrite(300)

	// pendingBytes should have accumulated for flush.
	if pending := cl.pendingBytes.Load(); pending != 500 {
		t.Fatalf("expected 500 pending bytes, got %d", pending)
	}

	cl.flush()

	// After flush, pending should be 0 and Redis should have 500.
	if pending := cl.pendingBytes.Load(); pending != 0 {
		t.Fatalf("expected 0 pending after flush, got %d", pending)
	}

	ctx := context.Background()
	total, err := store.AddBytes(ctx, "alice", 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 500 {
		t.Fatalf("expected 500 in Redis, got %d", total)
	}

	bw, err := store.GetBandwidthBytes(ctx, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bw != 500 {
		t.Fatalf("expected 500 bandwidth bytes in Redis, got %d", bw)
	}
}

func TestRelay_DeadlineEnforced(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:         store,
		user:          "alice",
		deadline:      time.Now().Add(50 * time.Millisecond),
		logger:        testLogger(),
		flushInterval: time.Hour,
	}

	clientConn, clientRemote := net.Pipe()
	backendConn, backendRemote := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- Relay(clientConn, backendConn, cl)
	}()

	// Slowly write data so the deadline expires mid-relay.
	go func() {
		for i := 0; i < 100; i++ {
			_, err := clientRemote.Write([]byte("x"))
			if err != nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		clientRemote.Close()
	}()

	// Drain the backend side.
	go func() {
		buf := make([]byte, 1024)
		for {
			_, err := backendRemote.Read(buf)
			if err != nil {
				break
			}
		}
	}()

	err := <-done
	backendRemote.Close()

	if err != errDeadlineExceeded {
		t.Fatalf("expected deadline exceeded, got: %v", err)
	}
}

func TestRelay_CombinedLimits(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:           store,
		user:            "alice",
		maxBytesPerConn: 50,
		bandwidthTiers:  []auth.BandwidthTier{{Bytes: 10000, Period: time.Hour}},
		deadline:        time.Now().Add(5 * time.Second),
		logger:          testLogger(),
		flushInterval:   time.Hour,
	}

	clientConn, clientRemote := net.Pipe()
	backendConn, backendRemote := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- Relay(clientConn, backendConn, cl)
	}()

	// Write more than per-connection limit — byte limit should trigger first.
	go func() {
		clientRemote.Write(make([]byte, 100))
		clientRemote.Close()
	}()

	buf := make([]byte, 200)
	backendRemote.Read(buf)
	backendRemote.Close()

	err := <-done
	if err != errByteLimitExceeded {
		t.Fatalf("expected byte limit exceeded (not deadline or bandwidth), got: %v", err)
	}
}

func TestConnLimits_BandwidthFlushError_DoesNotPanic(t *testing.T) {
	// Use a Redis store that will fail (closed connection).
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	store := NewRedisStore(rdb, "test:", metrics.Noop())

	cl := &ConnLimits{
		store:          store,
		user:           "alice",
		bandwidthTiers: []auth.BandwidthTier{{Bytes: 100, Period: time.Hour}},
		logger:         testLogger(),
		flushInterval:  time.Hour,
		done:           make(chan struct{}),
	}

	cl.ReportBytes(50)

	// Close miniredis to force errors.
	mr.Close()

	// flush should not panic; error is logged and swallowed.
	cl.flush()

	// limitErr should NOT be set (bandwidth check was skipped due to error).
	if err := cl.checkLimitErr(); err != nil {
		t.Fatalf("expected no limit error after flush failure, got: %v", err)
	}
}

func TestRelay_ByteLimitEnforced(t *testing.T) {
	store := setupConnTest(t)
	cl := &ConnLimits{
		store:           store,
		user:            "alice",
		maxBytesPerConn: 10,
		logger:          testLogger(),
		flushInterval:   time.Hour,
	}

	clientConn, clientRemote := net.Pipe()
	backendConn, backendRemote := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- Relay(clientConn, backendConn, cl)
	}()

	// Write more than the limit.
	go func() {
		clientRemote.Write(make([]byte, 20))
		clientRemote.Close()
	}()

	// Read whatever comes through.
	buf := make([]byte, 100)
	backendRemote.Read(buf)
	backendRemote.Close()

	err := <-done
	if err != errByteLimitExceeded {
		t.Fatalf("expected byte limit exceeded, got: %v", err)
	}
}
