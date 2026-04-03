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
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/testutil"
	"github.com/redoapp/waypoint/internal/tsdns"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
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

		// runServer uses srv.Start() (not Up), so the node may still be
		// logging in and registering with the control plane. Poll until
		// the local status shows a Tailscale IP (meaning login completed)
		// and the node appears in the control server.
		var node *tailcfg.Node
		regDeadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(regDeadline) {
			st, err := lc.Status(ctx)
			if err != nil {
				return fmt.Errorf("status: %w", err)
			}
			if st.Self != nil && len(st.TailscaleIPs) > 0 && !st.Self.PublicKey.IsZero() {
				node = control.Node(st.Self.PublicKey)
				if node != nil {
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if node == nil {
			return fmt.Errorf("node not found in control after 30s")
		}
		node.Tags = []string{"tag:waypoint"}
		control.UpdateNode(node)

		// Wait for the node to see its updated tags.
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			st, err := lc.Status(ctx)
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

	var testLevelVar slog.LevelVar
	testLevelVar.Set(slog.LevelDebug)
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &testLevelVar}))
	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(runCtx, configPath, lgr, &testLevelVar, afterTSStart)
	}()

	// Check for early startup failure.
	select {
	case err := <-errCh:
		t.Fatalf("runServer exited early: %v", err)
	case <-time.After(2 * time.Second):
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

// TestE2E_SplitDNS_ResolveViaTailscale verifies that the tsdns package
// correctly resolves hostnames through the Tailscale local API when DNS
// extra records are configured on the fake control plane. This is a
// regression test for tailscale/tailscale#5840 where tsnet.Server.Dial
// falls back to the system resolver for non-tailnet names.
func TestE2E_SplitDNS_ResolveViaTailscale(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// --- Fake Tailscale control plane with extra DNS records ---

	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
			// Route the suffix through MagicDNS (empty resolver list =
			// handled by the built-in resolver using ExtraRecords).
			Routes: map[string][]*dnstype.Resolver{
				"example.com": {},
			},
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: "db.example.com.", Value: "10.77.1.50"},
			},
		},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)

	// --- Start a tsnet node ---

	stateDir := filepath.Join(t.TempDir(), "dns-test")
	os.MkdirAll(stateDir, 0755)

	srv := &tsnet.Server{
		Dir:        stateDir,
		ControlURL: control.HTTPTestServer.URL,
		Hostname:   "dns-test-node",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { srv.Close() })

	if _, err := srv.Up(ctx); err != nil {
		t.Fatalf("tsnet Up: %v", err)
	}

	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatalf("LocalClient: %v", err)
	}

	// --- Verify: lc.QueryDNS resolves the extra record ---

	queryDNS := func(ctx context.Context, name, qtype string) ([]byte, error) {
		raw, _, err := lc.QueryDNS(ctx, name, qtype)
		return raw, err
	}

	ips, err := tsdns.LookupHost(ctx, queryDNS, "db.example.com")
	if err != nil {
		t.Fatalf("tsdns.LookupHost failed: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one IP")
	}
	if ips[0] != "10.77.1.50" {
		t.Fatalf("expected 10.77.1.50, got %s", ips[0])
	}

	// --- Verify: srv.Dial WITHOUT tsdns fails (demonstrates the bug) ---

	// The raw srv.Dial goes through userDialResolve which falls back to
	// the system resolver for non-tailnet names. This should fail because
	// the system resolver doesn't know about our DNS extra record.
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	_, srvDialErr := srv.Dial(dialCtx, "tcp", "db.example.com:5432")
	if srvDialErr == nil {
		// If srv.Dial succeeds, the upstream bug may have been fixed.
		t.Log("srv.Dial succeeded directly — tailscale/tailscale#5840 may be fixed")
	} else {
		t.Logf("srv.Dial failed as expected (confirms #5840): %v", srvDialErr)
	}

	// --- Verify: tsdns.NewDialer resolves correctly ---

	lookupFunc := tsdns.NewLookupFunc(queryDNS)
	resolved, err := lookupFunc(ctx, "db.example.com")
	if err != nil {
		t.Fatalf("tsdns lookupFunc failed: %v", err)
	}
	if resolved[0] != "10.77.1.50" {
		t.Fatalf("expected 10.77.1.50, got %s", resolved[0])
	}
}

// handleDNSQuery parses a raw DNS query and returns a response.
// If the question is db.example.internal. type A, it returns 10.99.0.1.
// Otherwise it returns NXDOMAIN.
func handleDNSQuery(query []byte) []byte {
	var parser dnsmessage.Parser
	hdr, err := parser.Start(query)
	if err != nil {
		return nil
	}

	q, err := parser.Question()
	if err != nil {
		return nil
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       hdr.ID,
			Response: true,
		},
		Questions: []dnsmessage.Question{q},
	}

	if q.Name.String() == "db.example.internal." && q.Type == dnsmessage.TypeA {
		resp.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   300,
			},
			Body: &dnsmessage.AResource{A: [4]byte{10, 99, 0, 1}},
		}}
	} else {
		resp.Header.RCode = dnsmessage.RCodeNameError
	}

	packed, _ := resp.Pack()
	return packed
}

// serveDNSUDP reads UDP packets from pc, handles them as DNS queries, and
// writes back responses. It returns when pc is closed.
func serveDNSUDP(pc net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := handleDNSQuery(buf[:n])
		if resp != nil {
			pc.WriteTo(resp, addr)
		}
	}
}

// buildDNSAQuery builds a raw DNS A query packet for the given FQDN.
func buildDNSAQuery(fqdn string) []byte {
	name, _ := dnsmessage.NewName(fqdn)
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, _ := msg.Pack()
	return packed
}

// TestE2E_SplitDNS_ForwarderTimeout proves that lc.QueryDNS cannot resolve
// names forwarded to a DNS server behind a subnet router. The forwarder uses
// net.ListenPacket (system stack) which cannot reach subnet-routed IPs in
// tsnet's userspace mode. Direct Tailscale UDP to the same DNS server works.
func TestE2E_SplitDNS_ForwarderTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// --- Test infrastructure ---

	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })

	// testcontrol assigns IPs as 100.64.{nodeID>>8}.{nodeID} where nodeID =
	// len(nodes)+1 at registration time. The subnet-router registers first, so
	// it gets nodeID=1 → 100.64.0.1.  We pre-set DNSConfig.Routes here, before
	// any node connects, to avoid a data race between the test mutating Routes
	// and testcontrol reading DNSConfig.Clone() in its map-response handler.
	const predictedSRIP = "100.64.0.1"

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap: derpMap,
		DNSConfig: &tailcfg.DNSConfig{
			Proxied: true,
			Routes: map[string][]*dnstype.Resolver{
				"example.internal": {{Addr: predictedSRIP}},
			},
		},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL := control.HTTPTestServer.URL

	// --- Start "subnet-router" tsnet node ---

	srDir := filepath.Join(t.TempDir(), "subnet-router")
	os.MkdirAll(srDir, 0755)

	srNode := &tsnet.Server{
		Dir:        srDir,
		ControlURL: controlURL,
		Hostname:   "subnet-router",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { srNode.Close() })

	if _, err := srNode.Up(ctx); err != nil {
		t.Fatalf("subnet-router Up: %v", err)
	}

	srLC, err := srNode.LocalClient()
	if err != nil {
		t.Fatalf("subnet-router LocalClient: %v", err)
	}

	srStatus, err := srLC.Status(ctx)
	if err != nil {
		t.Fatalf("subnet-router Status: %v", err)
	}
	srTSIP := srStatus.TailscaleIPs[0].String() // 100.x.y.z
	if srTSIP != predictedSRIP {
		t.Fatalf("subnet-router got IP %s, expected %s", srTSIP, predictedSRIP)
	}

	// Advertise subnet routes for this node.
	control.SetSubnetRoutes(srStatus.Self.PublicKey, []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/24"),
	})

	// --- Run DNS server on subnet-router's Tailscale IP ---

	pc, err := srNode.ListenPacket("udp", net.JoinHostPort(srTSIP, "53"))
	if err != nil {
		t.Fatalf("ListenPacket on subnet-router: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go serveDNSUDP(pc)

	// --- Start "client" tsnet node ---

	clientDir := filepath.Join(t.TempDir(), "client")
	os.MkdirAll(clientDir, 0755)

	clientNode := &tsnet.Server{
		Dir:        clientDir,
		ControlURL: controlURL,
		Hostname:   "dns-fwd-client",
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

	// Wait for subnet-router peer to appear.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, err := clientLC.Status(ctx)
		if err != nil {
			t.Fatalf("client status: %v", err)
		}
		for _, peer := range st.Peer {
			if peer.HostName == "subnet-router" {
				goto peerFound
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("timed out waiting for subnet-router peer")
peerFound:

	// --- Assertion 1: Direct UDP to the DNS server works (positive control) ---

	conn, err := clientNode.Dial(ctx, "udp", net.JoinHostPort(srTSIP, "53"))
	if err != nil {
		t.Fatalf("client Dial UDP to subnet-router DNS: %v", err)
	}
	defer conn.Close()

	query := buildDNSAQuery("db.example.internal.")
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("write DNS query: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	respBuf := make([]byte, 512)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("read DNS response: %v", err)
	}

	// Parse response to verify we got 10.99.0.1.
	var respParser dnsmessage.Parser
	if _, err := respParser.Start(respBuf[:n]); err != nil {
		t.Fatalf("parse DNS response header: %v", err)
	}
	if err := respParser.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	ans, err := respParser.AllAnswers()
	if err != nil {
		t.Fatalf("parse answers: %v", err)
	}
	if len(ans) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(ans))
	}
	aBody, ok := ans[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("expected A record, got %T", ans[0].Body)
	}
	if aBody.A != [4]byte{10, 99, 0, 1} {
		t.Fatalf("expected 10.99.0.1, got %v", aBody.A)
	}
	t.Log("Assertion 1 passed: direct UDP DNS query to subnet-router resolved correctly")

	// --- Assertion 2: lc.QueryDNS fails (the forwarding bug) ---

	queryCtx, queryCancel := context.WithTimeout(ctx, 10*time.Second)
	defer queryCancel()

	_, _, queryErr := clientLC.QueryDNS(queryCtx, "db.example.internal.", "A")
	if queryErr != nil {
		t.Logf("Assertion 2 passed: lc.QueryDNS failed as expected (forwarder cannot reach subnet-routed IP): %v", queryErr)
	} else {
		t.Fatal("lc.QueryDNS unexpectedly succeeded — if this happens, the upstream Tailscale forwarder bug may be fixed; update the test")
	}

	// --- Assertion 3: NewRoutedQueryFunc succeeds via custom forwarder ---

	dnsRoutes, err := tsdns.FetchDNSRoutes(ctx, func(ctx context.Context, mask ipn.NotifyWatchOpt) (tsdns.IPNBusWatcher, error) {
		return clientLC.WatchIPNBus(ctx, mask)
	})
	if err != nil {
		t.Fatalf("FetchDNSRoutes: %v", err)
	}
	t.Logf("DNS routes: %v", dnsRoutes)

	fallback := func(ctx context.Context, name, qtype string) ([]byte, error) {
		raw, _, err := clientLC.QueryDNS(ctx, name, qtype)
		return raw, err
	}
	routedQuery := tsdns.NewRoutedQueryFunc(fallback, clientNode.Dial, dnsRoutes)

	routedCtx, routedCancel := context.WithTimeout(ctx, 10*time.Second)
	defer routedCancel()

	ips, err := tsdns.LookupHost(routedCtx, routedQuery, "db.example.internal")
	if err != nil {
		t.Fatalf("Assertion 3 failed: routed query failed: %v", err)
	}
	if len(ips) == 0 || ips[0] != "10.99.0.1" {
		t.Fatalf("Assertion 3 failed: expected 10.99.0.1, got %v", ips)
	}
	t.Log("Assertion 3 passed: NewRoutedQueryFunc resolved db.example.internal to 10.99.0.1 via custom forwarder")
}
