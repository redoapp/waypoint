//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/testutil"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// TestE2E_ServiceListener_ProxyProto is a full end-to-end test that calls the
// real run() function (the production code path in main.go). It verifies that
// service listeners with PROXY protocol correctly pass the peer's real
// Tailscale IP to WhoIs for authentication, rather than 127.0.0.1.
//
// This is a regression test for the "peer not found" bug on service connections.
func TestE2E_ServiceListener_ProxyProto(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// --- Test infrastructure ---

	// Tailscale test control plane.
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL := control.HTTPTestServer.URL

	// Set waypoint capabilities for all peers.
	capRule := auth.CapRule{
		Backends: []string{"echo-svc"},
		Limits:   &auth.LimitsCap{MaxConns: 5},
	}
	capJSON, err := json.Marshal(capRule)
	if err != nil {
		t.Fatalf("marshal cap rule: %v", err)
	}
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{
		tailcfg.PeerCapability(auth.WaypointCap): {tailcfg.RawMessage(capJSON)},
	})

	// Redis (via testcontainer).
	rdb := testutil.RedisClient(t)

	// Backend echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { echoLn.Close() })

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	// --- Config file ---

	stateDir := filepath.Join(t.TempDir(), "wp-state")
	os.MkdirAll(stateDir, 0755)

	configContent := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-e2e"
control_url = "%s"
state_dir = "%s"
ephemeral = true

[redis]
address = "%s"
key_prefix = "e2e:"

[[listeners]]
name = "echo-svc"
service = "svc:echo-e2e"
listen = ":7778"
mode = "tcp"
backend = "%s"
`, controlURL, stateDir, rdb.Options().Addr, echoLn.Addr().String())

	configPath := filepath.Join(t.TempDir(), "waypoint.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// --- Start waypoint via the real run() code path ---

	// afterTSStart sets tags on the waypoint node via the test control plane.
	// The test control doesn't process AdvertiseTags, so tags must be set
	// after the node registers but before ListenService is called.
	afterTSStart := func(srv *tsnet.Server) error {
		lc, err := srv.LocalClient()
		if err != nil {
			return fmt.Errorf("local client: %w", err)
		}
		st, err := lc.Status(ctx)
		if err != nil {
			return fmt.Errorf("status: %w", err)
		}

		node := control.Node(st.Self.PublicKey)
		if node == nil {
			return fmt.Errorf("node not found in control")
		}
		node.Tags = []string{"tag:waypoint"}
		control.UpdateNode(node)

		// Wait for the node to see its updated tags.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			st, err = lc.Status(ctx)
			if err != nil {
				return fmt.Errorf("status poll: %w", err)
			}
			if st.Self.Tags != nil && st.Self.Tags.Len() > 0 {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return fmt.Errorf("timed out waiting for node to see its tags")
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(runCtx, configPath, lgr, afterTSStart)
	}()

	// Check for early startup failure.
	select {
	case err := <-errCh:
		t.Fatalf("runServer exited early: %v", err)
	case <-time.After(1 * time.Second):
		// Give it a moment — if it hasn't failed, it's likely starting up.
	}

	// --- Client node ---

	clientDir := filepath.Join(t.TempDir(), "client")
	os.MkdirAll(clientDir, 0755)

	clientNode := &tsnet.Server{
		Dir:        clientDir,
		ControlURL: controlURL,
		Hostname:   "e2e-client",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { clientNode.Close() })

	if _, err := clientNode.Up(ctx); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	clientLC, err := clientNode.LocalClient()
	if err != nil {
		t.Fatalf("client LocalClient: %v", err)
	}

	// Wait for the waypoint peer to appear.
	var waypointIP string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, err := clientLC.Status(ctx)
		if err != nil {
			t.Fatalf("client status: %v", err)
		}
		for _, peer := range st.Peer {
			if peer.HostName == "waypoint-e2e" {
				waypointIP = peer.TailscaleIPs[0].String()
				break
			}
		}
		if waypointIP != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if waypointIP == "" {
		t.Fatal("timed out waiting for waypoint-e2e peer")
	}

	// --- Verify: dial the service and echo data ---

	conn, err := clientNode.Dial(ctx, "tcp", fmt.Sprintf("%s:7778", waypointIP))
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()

	// If auth fails (WhoIs sees 127.0.0.1 → "peer not found"), the proxy
	// closes the connection immediately and the read below will fail.
	msg := "hello-e2e-proxyproto\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("echo read failed (WhoIs likely received 127.0.0.1 instead of real peer IP): %v", err)
	}
	if string(buf[:n]) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf[:n]), msg)
	}

	// --- Shutdown ---
	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runServer: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}
