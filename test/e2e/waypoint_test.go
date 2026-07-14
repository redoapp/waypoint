//go:build integration

package e2e

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/server"
	"github.com/redoapp/waypoint/internal/testutil"
	"github.com/redoapp/waypoint/internal/tsdns"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
)

// TestE2E_ServiceListener_ProxyProto is a full end-to-end test that calls the
// real server runner used by cmd/waypoint. It verifies that
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
		Limits: &auth.LimitsCap{MaxConns: 5},
		Backends: map[string]auth.BackendCap{
			"echo-svc": {},
		},
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

	// --- Start waypoint via the real server path ---

	const serviceName = tailcfg.ServiceName("svc:echo-e2e")
	const serviceVIP = "100.11.22.33"

	// afterTSStart configures the test control plane for services:
	//   - tags the node (ListenService requires tagged nodes)
	//   - sets NodeAttrServiceHost capability with VIP mapping
	//   - advertises subnet route for the service VIP
	//   - adds DNS record for the service FQDN
	// This mirrors the setup in tsnet's TestListenService.
	afterTSStart := func(srv *tsnet.Server) error {
		lc, err := srv.LocalClient()
		if err != nil {
			return fmt.Errorf("local client: %w", err)
		}

		// RunServer uses srv.Start() (not Up), so the node may still be
		// logging in and registering with the control plane. Poll until
		// the local status shows a Tailscale IP (meaning login completed)
		// and the node appears in the control server.
		var node *tailcfg.Node
		var nodeKey key.NodePublic
		regDeadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(regDeadline) {
			st, err := lc.Status(ctx)
			if err != nil {
				return fmt.Errorf("status: %w", err)
			}
			if st.Self != nil && len(st.TailscaleIPs) > 0 && !st.Self.PublicKey.IsZero() {
				nodeKey = st.Self.PublicKey
				node = control.Node(nodeKey)
				if node != nil {
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
		if node == nil {
			return fmt.Errorf("node not found in control after 30s")
		}

		// Tag the node (required by ListenService).
		node.Tags = []string{"tag:waypoint"}
		control.UpdateNode(node)

		// Set service-host capability: maps service name → VIP.
		// Include the default testcontrol caps so the override doesn't clear them.
		serviceHostCaps := map[tailcfg.ServiceName]views.Slice[netip.Addr]{
			serviceName: views.SliceOf([]netip.Addr{netip.MustParseAddr(serviceVIP)}),
		}
		svcCapJSON, err := json.Marshal(serviceHostCaps)
		if err != nil {
			return fmt.Errorf("marshal service host caps: %w", err)
		}
		control.SetNodeCapMap(nodeKey, tailcfg.NodeCapMap{
			tailcfg.NodeAttrServiceHost:                       {tailcfg.RawMessage(svcCapJSON)},
			tailcfg.CapabilityHTTPS:                           {},
			tailcfg.NodeAttrFunnel:                            {},
			tailcfg.CapabilityFileSharing:                     {},
			tailcfg.CapabilityFunnelPorts + "?ports=8080,443": {},
		})

		// Advertise subnet route for the service VIP.
		control.SetSubnetRoutes(nodeKey, []netip.Prefix{
			netip.MustParsePrefix(serviceVIP + "/32"),
		})

		// Add DNS record so the service FQDN resolves to the VIP.
		control.AddDNSRecords(tailcfg.DNSRecord{
			Name:  string(serviceName.WithoutPrefix()) + "." + control.MagicDNSDomain,
			Value: serviceVIP,
		})

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
		errCh <- server.RunServer(runCtx, configPath, lgr, &testLevelVar, afterTSStart)
	}()

	// Check for early startup failure.
	select {
	case err := <-errCh:
		t.Fatalf("RunServer exited early: %v", err)
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

	// Accept routes advertised by the service host (equivalent to --accept-routes).
	if _, err := clientLC.EditPrefs(ctx, &ipn.MaskedPrefs{
		RouteAllSet: true,
		Prefs:       ipn.Prefs{RouteAll: true},
	}); err != nil {
		t.Fatalf("client EditPrefs RouteAll: %v", err)
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

	// Dial the service by its FQDN (the VIP), not the node's Tailscale IP.
	// Retry because RunServer may still be setting up the listener.
	serviceFQDN := string(serviceName.WithoutPrefix()) + "." + control.MagicDNSDomain
	var conn net.Conn
	dialDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(dialDeadline) {
		conn, err = clientNode.Dial(ctx, "tcp", fmt.Sprintf("%s:7778", serviceFQDN))
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
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
	conn.Close() // close before cancel so the server doesn't block draining
	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}

// TestE2E_TCPProxy_PortMap verifies that port_map listeners work end-to-end
// through the real server path. It starts two echo backends, writes
// a TOML config with port_map mapping two listen ports to those backends, and
// verifies that data flows through both mapped ports. This is a regression
// test for the TOML integer-key bug where port_map silently produced an empty
// map, causing only a single (broken) listener to be created.
func TestE2E_TCPProxy_PortMap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// --- Test infrastructure ---

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
		Limits: &auth.LimitsCap{MaxConns: 5},
		Backends: map[string]auth.BackendCap{
			"portmap-echo": {},
		},
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

	// Two backend echo servers on separate ports.
	echoLn1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo1 listen: %v", err)
	}
	t.Cleanup(func() { echoLn1.Close() })

	echoLn2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo2 listen: %v", err)
	}
	t.Cleanup(func() { echoLn2.Close() })

	for _, ln := range []net.Listener{echoLn1, echoLn2} {
		ln := ln
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					io.Copy(conn, conn)
				}()
			}
		}()
	}

	_, echo1Port, _ := net.SplitHostPort(echoLn1.Addr().String())
	_, echo2Port, _ := net.SplitHostPort(echoLn2.Addr().String())

	// --- Config file with port_map ---

	stateDir := filepath.Join(t.TempDir(), "wp-state")
	os.MkdirAll(stateDir, 0755)

	configContent := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-portmap-e2e"
control_url = "%s"
state_dir = "%s"
ephemeral = true

[redis]
address = "%s"
key_prefix = "e2e-pm:"

[[listeners]]
name = "portmap-echo"
mode = "tcp"
backend = "127.0.0.1"
port_map = { "7780" = %s, "7781" = %s }
`, controlURL, stateDir, rdb.Options().Addr, echo1Port, echo2Port)

	configPath := filepath.Join(t.TempDir(), "waypoint.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// --- Start waypoint via the real server path ---

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	var testLevelVar slog.LevelVar
	testLevelVar.Set(slog.LevelDebug)
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &testLevelVar}))
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.RunServer(runCtx, configPath, lgr, &testLevelVar, nil)
	}()

	// Check for early startup failure.
	select {
	case err := <-errCh:
		t.Fatalf("RunServer exited early: %v", err)
	case <-time.After(2 * time.Second):
	}

	// --- Client node ---

	clientDir := filepath.Join(t.TempDir(), "client")
	os.MkdirAll(clientDir, 0755)

	clientNode := &tsnet.Server{
		Dir:        clientDir,
		ControlURL: controlURL,
		Hostname:   "e2e-pm-client",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { clientNode.Close() })

	if _, err := clientNode.Up(ctx); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	// Wait for the waypoint peer to appear.
	var waypointIP string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		st, err := clientNode.LocalClient()
		if err != nil {
			t.Fatalf("client LocalClient: %v", err)
		}
		status, err := st.Status(ctx)
		if err != nil {
			t.Fatalf("client status: %v", err)
		}
		for _, peer := range status.Peer {
			if peer.HostName == "waypoint-portmap-e2e" {
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
		t.Fatal("timed out waiting for waypoint-portmap-e2e peer")
	}

	// --- Verify: dial both mapped ports and echo data ---

	for _, port := range []string{"7780", "7781"} {
		port := port
		t.Run("port_"+port, func(t *testing.T) {
			var conn net.Conn
			dialDeadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(dialDeadline) {
				conn, err = clientNode.Dial(ctx, "tcp", fmt.Sprintf("%s:%s", waypointIP, port))
				if err == nil {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("client dial port %s: %v", port, err)
			}
			defer conn.Close()

			msg := fmt.Sprintf("hello-portmap-%s\n", port)
			if _, err := conn.Write([]byte(msg)); err != nil {
				t.Fatalf("write: %v", err)
			}

			buf := make([]byte, len(msg))
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := io.ReadFull(conn, buf)
			if err != nil {
				t.Fatalf("echo read failed on port %s: %v", port, err)
			}
			if string(buf[:n]) != msg {
				t.Fatalf("echo mismatch on port %s: got %q, want %q", port, string(buf[:n]), msg)
			}
		})
	}

	// --- Shutdown ---
	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer: %v", err)
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

// serveDNSTCP accepts TCP connections and handles DNS-over-TCP queries
// (2-byte length prefix per RFC 7766). It returns when ln is closed.
func serveDNSTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				var length uint16
				if err := binary.Read(c, binary.BigEndian, &length); err != nil {
					return
				}
				buf := make([]byte, length)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				resp := handleDNSQuery(buf)
				if resp == nil {
					return
				}
				binary.Write(c, binary.BigEndian, uint16(len(resp)))
				c.Write(resp)
			}
		}(conn)
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

// TestE2E_SplitDNS_ForwarderTimeout validates DNS resolution for names
// forwarded to a DNS server behind a subnet router. It verifies that both
// lc.QueryDNS and our custom NewRoutedQueryFunc correctly resolve names
// via the subnet-routed DNS server.
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

	// --- Run DNS server on subnet-router's Tailscale IP (UDP + TCP) ---

	pc, err := srNode.ListenPacket("udp", net.JoinHostPort(srTSIP, "53"))
	if err != nil {
		t.Fatalf("ListenPacket on subnet-router: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go serveDNSUDP(pc)

	tcpLn, err := srNode.Listen("tcp", net.JoinHostPort(srTSIP, "53"))
	if err != nil {
		t.Fatalf("Listen TCP on subnet-router: %v", err)
	}
	t.Cleanup(func() { tcpLn.Close() })
	go serveDNSTCP(tcpLn)

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

	// --- Assertion 2: lc.QueryDNS resolves via built-in forwarder ---

	queryCtx, queryCancel := context.WithTimeout(ctx, 10*time.Second)
	defer queryCancel()

	_, _, queryErr := clientLC.QueryDNS(queryCtx, "db.example.internal.", "A")
	if queryErr != nil {
		t.Fatalf("Assertion 2 failed: lc.QueryDNS could not resolve: %v", queryErr)
	}
	t.Log("Assertion 2 passed: lc.QueryDNS resolved via built-in forwarder")

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
	clientV4, _ := clientNode.TailscaleIPs()
	clientListenPacket := func(network, addr string) (net.PacketConn, error) {
		return clientNode.ListenPacket(network, net.JoinHostPort(clientV4.String(), "0"))
	}
	routedQuery := tsdns.NewRoutedQueryFunc(fallback, clientListenPacket, dnsRoutes)

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

// tsnetContextDialer adapts a tsnet.Server to the mongo driver's ContextDialer
// so the MongoDB client dials the waypoint listener through the tailnet.
type tsnetContextDialer struct{ s *tsnet.Server }

func (d tsnetContextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.s.Dial(ctx, network, address)
}

// TestE2E_MongoSharded_ReadWrite is a full end-to-end test that runs the real
// server against a sharded MongoDB cluster (config-server RS + two shard RSs +
// mongos routers). A client connects through the tailnet to the waypoint
// MongoDB listener (topology = "sharded"), which provisions a dynamic user via
// the mongos and proxies read/write traffic to the sharded backend.
//
// This is heavy (spins up an 11-container sharded cluster plus a mock Tailscale
// control plane); run with an extended timeout, e.g.:
//
//	go test -tags integration -run 'TestE2E_MongoSharded' -timeout 300s ./test/e2e
func TestE2E_MongoSharded_ReadWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 280*time.Second)
	defer cancel()

	// --- Sharded MongoDB backend ---
	sharded := testutil.MongoDBShardedCluster(t)
	mongosBackend := sharded.Mongos[0]

	// --- Test infrastructure ---
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

	// Grant readwrite on e2edb through the "mongo-sharded" backend.
	capRule := auth.CapRule{
		Limits: &auth.LimitsCap{MaxConns: 10},
		Backends: map[string]auth.BackendCap{
			"mongo-sharded": {
				Mongo: &auth.MongoCap{
					Databases: map[string]auth.MongoDBPermissions{
						"e2edb": {Permissions: []string{"readwrite"}},
					},
				},
			},
		},
	}
	capJSON, err := json.Marshal(capRule)
	if err != nil {
		t.Fatalf("marshal cap rule: %v", err)
	}
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{
		tailcfg.PeerCapability(auth.WaypointCap): {tailcfg.RawMessage(capJSON)},
	})

	rdb := testutil.RedisClient(t)

	// --- Config file: sharded mongodb listener ---
	stateDir := filepath.Join(t.TempDir(), "wp-state")
	os.MkdirAll(stateDir, 0755)

	configContent := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-mongo-e2e"
control_url = "%s"
state_dir = "%s"
ephemeral = true

[redis]
address = "%s"
key_prefix = "e2e-mongo:"

[[listeners]]
name = "mongo-sharded"
mode = "mongodb"

[listeners.mongodb]
admin_user = "admin"
admin_password = "adminpass"
auth_database = "admin"
topology = "sharded"

[[listeners.mongodb.members]]
backend = "%s"
listen = ":27020"
`, controlURL, stateDir, rdb.Options().Addr, mongosBackend)

	configPath := filepath.Join(t.TempDir(), "waypoint.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// --- Start waypoint via the real server path ---
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	var testLevelVar slog.LevelVar
	testLevelVar.Set(slog.LevelInfo)
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &testLevelVar}))
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.RunServer(runCtx, configPath, lgr, &testLevelVar, nil)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("RunServer exited early: %v", err)
	case <-time.After(2 * time.Second):
	}

	// --- Client node ---
	clientDir := filepath.Join(t.TempDir(), "client")
	os.MkdirAll(clientDir, 0755)

	clientNode := &tsnet.Server{
		Dir:        clientDir,
		ControlURL: controlURL,
		Hostname:   "e2e-mongo-client",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { clientNode.Close() })

	if _, err := clientNode.Up(ctx); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	// Wait for the waypoint peer to appear.
	var waypointIP string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		lc, err := clientNode.LocalClient()
		if err != nil {
			t.Fatalf("client LocalClient: %v", err)
		}
		status, err := lc.Status(ctx)
		if err != nil {
			t.Fatalf("client status: %v", err)
		}
		for _, peer := range status.Peer {
			if peer.HostName == "waypoint-mongo-e2e" {
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
		t.Fatal("timed out waiting for waypoint-mongo-e2e peer")
	}

	// --- Verify: connect a mongo client through the tailnet and read/write ---
	uri := fmt.Sprintf("mongodb://%s:27020/e2edb?directConnection=true&serverSelectionTimeoutMS=15000", waypointIP)
	clientOpts := options.Client().ApplyURI(uri).SetDialer(tsnetContextDialer{clientNode})

	var mc *mongo.Client
	dialDeadline := time.Now().Add(40 * time.Second)
	for {
		mc, err = mongo.Connect(clientOpts)
		if err == nil {
			if pingErr := mc.Ping(ctx, nil); pingErr == nil {
				break
			} else {
				err = pingErr
				mc.Disconnect(ctx)
			}
		}
		if time.Now().After(dialDeadline) {
			t.Fatalf("connect to waypoint mongo listener through tailnet: %v", err)
		}
		time.Sleep(1 * time.Second)
	}
	defer mc.Disconnect(context.Background())

	coll := mc.Database("e2edb").Collection("items")
	if _, err := coll.InsertOne(ctx, bson.D{{Key: "name", Value: "e2e-sharded"}, {Key: "n", Value: 42}}); err != nil {
		t.Fatalf("insert through sharded waypoint proxy: %v", err)
	}

	var doc bson.M
	if err := coll.FindOne(ctx, bson.D{{Key: "name", Value: "e2e-sharded"}}).Decode(&doc); err != nil {
		t.Fatalf("find through sharded waypoint proxy: %v", err)
	}
	if doc["n"] != int32(42) {
		t.Fatalf("read-back mismatch: got %+v", doc)
	}

	// --- Shutdown ---
	mc.Disconnect(context.Background())
	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}

// seedOpenSearchDoc indexes a document into the backend as admin (refreshing so
// it is immediately searchable). It talks to the backend container directly,
// bypassing waypoint, purely to establish test data.
func seedOpenSearchDoc(t *testing.T, backend, index, jsonDoc string) {
	t.Helper()
	url := fmt.Sprintf("http://%s/%s/_doc?refresh=true", backend, index)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(jsonDoc))
	if err != nil {
		t.Fatalf("seed request: %v", err)
	}
	req.SetBasicAuth(testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("seed %s: %v", index, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("seed %s status = %d: %s", index, resp.StatusCode, body)
	}
}

// TestE2E_OpenSearch_ProvisionAndProxy is a full end-to-end test that runs the
// real server against a live OpenSearch backend. A client makes HTTP requests
// through the tailnet to the waypoint OpenSearch listener (database provision
// mode). Waypoint authenticates the caller via Tailscale WhoIs, reads the
// redo.com/cap/waypoint grant, dynamically provisions a scoped backend user via
// the OpenSearch Security API, and proxies the request with the injected backend
// credentials. It verifies that:
//   - an authorized read-only grant can hit cluster health and search a
//     permitted index through the proxy, and
//   - the same grant is denied a write, proving scoping is enforced end-to-end.
func TestE2E_OpenSearch_ProvisionAndProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancel()

	// --- OpenSearch backend ---
	backend := testutil.OpenSearchBackend(t)
	seedOpenSearchDoc(t, backend, "logs-2026", `{"message":"e2e-hello","level":"info"}`)

	// --- Test infrastructure ---
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

	// Grant read-only access on logs-* plus cluster monitoring through the
	// "search" backend.
	capRule := auth.CapRule{
		Limits: &auth.LimitsCap{MaxConns: 10},
		Backends: map[string]auth.BackendCap{
			"search": {
				OpenSearch: &auth.OpenSearchCap{
					ClusterPermissions: []string{"cluster_monitor"},
					Indices: map[string]auth.OpenSearchIndexPermissions{
						"logs-*": {Permissions: []string{"readonly"}},
					},
				},
			},
		},
	}
	capJSON, err := json.Marshal(capRule)
	if err != nil {
		t.Fatalf("marshal cap rule: %v", err)
	}
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{
		tailcfg.PeerCapability(auth.WaypointCap): {tailcfg.RawMessage(capJSON)},
	})

	rdb := testutil.RedisClient(t)

	// --- Config file: opensearch listener in database provision mode ---
	stateDir := filepath.Join(t.TempDir(), "wp-state")
	os.MkdirAll(stateDir, 0755)

	configContent := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-opensearch-e2e"
control_url = "%s"
state_dir = "%s"
ephemeral = true

[redis]
address = "%s"
key_prefix = "e2e-opensearch:"

[[listeners]]
name = "search"
listen = ":9200"
mode = "opensearch"
backend = "%s"
advertise = "waypoint-opensearch-e2e:9200"
tls_mode = "off"

[listeners.opensearch]
admin_user = "%s"
admin_password = "%s"
user_prefix = "wp_os_"
user_ttl = "24h"

[listeners.opensearch.provision]
mode = "database"
`, controlURL, stateDir, rdb.Options().Addr, backend, testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword)

	configPath := filepath.Join(t.TempDir(), "waypoint.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// --- Start waypoint via the real server path ---
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	var testLevelVar slog.LevelVar
	testLevelVar.Set(slog.LevelInfo)
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &testLevelVar}))
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.RunServer(runCtx, configPath, lgr, &testLevelVar, nil)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("RunServer exited early: %v", err)
	case <-time.After(2 * time.Second):
	}

	// --- Client node ---
	clientDir := filepath.Join(t.TempDir(), "client")
	os.MkdirAll(clientDir, 0755)

	clientNode := &tsnet.Server{
		Dir:        clientDir,
		ControlURL: controlURL,
		Hostname:   "e2e-opensearch-client",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	t.Cleanup(func() { clientNode.Close() })

	if _, err := clientNode.Up(ctx); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	// Wait for the waypoint peer to appear.
	var waypointIP string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		lc, err := clientNode.LocalClient()
		if err != nil {
			t.Fatalf("client LocalClient: %v", err)
		}
		status, err := lc.Status(ctx)
		if err != nil {
			t.Fatalf("client status: %v", err)
		}
		for _, peer := range status.Peer {
			if peer.HostName == "waypoint-opensearch-e2e" {
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
		t.Fatal("timed out waiting for waypoint-opensearch-e2e peer")
	}

	// --- HTTP client that dials the waypoint listener through the tailnet ---
	httpClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: clientNode.Dial,
		},
	}
	base := fmt.Sprintf("http://%s:9200", waypointIP)

	// osDo issues a request through the tailnet. Clients present a bogus
	// Authorization header, which waypoint must strip and replace with the
	// provisioned backend credentials.
	osDo := func(method, path, body string) (int, []byte) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, reqErr := http.NewRequestWithContext(ctx, method, base+path, rdr)
		if reqErr != nil {
			t.Fatalf("build %s %s: %v", method, path, reqErr)
		}
		req.Header.Set("Authorization", "Basic bogus-client-credential")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, doErr := httpClient.Do(req)
		if doErr != nil {
			return 0, []byte(doErr.Error())
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}

	// 1. Cluster health through the proxy — retry until the listener is up and
	//    the dynamic user has been provisioned.
	var healthStatus int
	var healthBody []byte
	dialDeadline := time.Now().Add(60 * time.Second)
	for {
		healthStatus, healthBody = osDo(http.MethodGet, "/_cluster/health", "")
		if healthStatus == http.StatusOK {
			break
		}
		if time.Now().After(dialDeadline) {
			t.Fatalf("cluster health through waypoint never succeeded: status=%d body=%s", healthStatus, healthBody)
		}
		time.Sleep(1 * time.Second)
	}

	// 2. Search the permitted index — should return the seeded document.
	searchStatus, searchBody := osDo(http.MethodGet, "/logs-2026/_search", "")
	if searchStatus != http.StatusOK {
		t.Fatalf("search through waypoint status = %d: %s", searchStatus, searchBody)
	}
	if !strings.Contains(string(searchBody), "e2e-hello") {
		t.Fatalf("search did not return the seeded document: %s", searchBody)
	}

	// 3. A write must be denied — the grant is read-only, proving the
	//    provisioned role's scoping is enforced through the full stack.
	writeStatus, writeBody := osDo(http.MethodPost, "/logs-2026/_doc", `{"message":"should-be-denied"}`)
	if writeStatus != http.StatusForbidden {
		t.Fatalf("read-only write status = %d (want 403): %s", writeStatus, writeBody)
	}

	// --- Shutdown ---
	// Close the keep-alive connection so the proxy's connection handler unblocks
	// and the server can drain and exit.
	httpClient.CloseIdleConnections()
	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}
