//go:build integration

package restrict_test

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

func TestIntegration_Relay_BandwidthTracking(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := restrict.NewTracker(store, metrics.Noop(), logger)
	ctx := context.Background()

	limits := auth.MergedLimits{
		BandwidthTiers: []auth.BandwidthTier{{Bytes: 100_000, Period: time.Hour}},
	}
	cl := tracker.WrapConn(ctx, "relay_bw_user", limits)
	cl.SetFlushIntervalForTest(50 * time.Millisecond)

	clientConn, clientRemote := net.Pipe()
	backendConn, backendRemote := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- restrict.Relay(clientConn, backendConn, cl)
	}()

	payload := make([]byte, 1000)
	go func() {
		clientRemote.Write(payload)
		clientRemote.Close()
	}()

	buf := make([]byte, 2000)
	total := 0
	for {
		n, err := backendRemote.Read(buf[total:])
		total += n
		if err != nil {
			break
		}
	}
	backendRemote.Close()
	<-done

	if total != 1000 {
		t.Fatalf("expected 1000 bytes relayed, got %d", total)
	}

	time.Sleep(100 * time.Millisecond)

	bw, err := store.GetBandwidthBytes(ctx, "relay_bw_user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bw == 0 {
		t.Fatal("expected bandwidth bytes to be tracked in Redis, got 0")
	}
}

func TestIntegration_Relay_BandwidthLimitEnforced(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := restrict.NewTracker(store, metrics.Noop(), logger)
	ctx := context.Background()

	limits := auth.MergedLimits{
		BandwidthTiers: []auth.BandwidthTier{{Bytes: 500, Period: time.Hour}},
	}
	cl := tracker.WrapConn(ctx, "relay_limit_user", limits)
	cl.SetFlushIntervalForTest(10 * time.Millisecond)

	clientConn, clientRemote := net.Pipe()
	backendConn, backendRemote := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- restrict.Relay(clientConn, backendConn, cl)
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_, err := clientRemote.Write(make([]byte, 100))
			if err != nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		clientRemote.Close()
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			_, err := backendRemote.Read(buf)
			if err != nil {
				break
			}
		}
	}()

	<-done
	backendRemote.Close()

	bw, err := store.GetBandwidthBytes(ctx, "relay_limit_user", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bw == 0 {
		t.Fatal("expected some bandwidth bytes tracked")
	}
}

func TestIntegration_ConnLimits_FlushToRealRedis(t *testing.T) {
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "inttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := restrict.NewTracker(store, metrics.Noop(), logger)
	ctx := context.Background()

	limits := auth.MergedLimits{}
	cl := tracker.WrapConn(ctx, "flush_user", limits)
	cl.SetFlushIntervalForTest(20 * time.Millisecond)

	cl.Start()

	// Report bytes in small increments.
	for i := 0; i < 10; i++ {
		if err := cl.ReportBytes(100); err != nil {
			t.Fatalf("report bytes: %v", err)
		}
	}

	// Wait for flush.
	time.Sleep(100 * time.Millisecond)
	cl.Stop()

	// Verify aggregate bytes in Redis.
	total, err := store.AddBytes(ctx, "flush_user", 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1000 {
		t.Fatalf("expected 1000 bytes in Redis after flush, got %d", total)
	}
}
