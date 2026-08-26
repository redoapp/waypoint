//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// TestE2E_WebConsole_RealTailscaleIdentity drives the browser console the way
// a browser does: over the tailnet, with identity resolved by a real WhoIs
// against the mock control plane and permissions taken from a real
// capability grant.
//
// This is what makes the console testable without a production seam. Every
// request below is authorized the same way a deployed one would be.
func TestE2E_WebConsole_RealTailscaleIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// --- Postgres backend with a schema worth completing against ---
	pgConnStr, pgBackend := testutil.PostgresBackend(t)

	adminConn, err := pgx.Connect(ctx, pgConnStr)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	// A second database, so the console's database picker is exercised.
	// Provisioning has to grant in each target database for this to work.
	for _, stmt := range []string{
		`DROP DATABASE IF EXISTS analytics WITH (FORCE)`,
		`CREATE DATABASE analytics`,
	} {
		if _, err := adminConn.Exec(ctx, stmt); err != nil {
			adminConn.Close(ctx)
			t.Fatalf("create analytics: %v", err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), pgConnStr)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), `DROP DATABASE IF EXISTS analytics WITH (FORCE)`)
	})
	analyticsConn, err := pgx.Connect(ctx, strings.Replace(pgConnStr, "/waypoint_test", "/analytics", 1))
	if err != nil {
		adminConn.Close(ctx)
		t.Fatalf("connect to analytics: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE events (id bigserial PRIMARY KEY, kind text)`,
		`INSERT INTO events (kind) SELECT 'click' FROM generate_series(1, 7)`,
	} {
		if _, err := analyticsConn.Exec(ctx, stmt); err != nil {
			analyticsConn.Close(ctx)
			adminConn.Close(ctx)
			t.Fatalf("seed analytics: %v", err)
		}
	}
	analyticsConn.Close(ctx)

	for _, stmt := range []string{
		`DROP TABLE IF EXISTS shipments, orders, customers CASCADE`,
		`CREATE TABLE customers (id bigserial PRIMARY KEY, email text, name text)`,
		`COMMENT ON COLUMN customers.email IS 'Primary contact address.'`,
		`CREATE TABLE orders (id bigserial PRIMARY KEY,
		    customer_id bigint NOT NULL REFERENCES customers(id), total numeric)`,
		`CREATE TABLE shipments (id bigserial PRIMARY KEY,
		    order_id bigint NOT NULL REFERENCES orders(id), carrier text)`,
		`INSERT INTO customers (email, name) VALUES ('a@example.com','Ann'),('b@example.com','Bo')`,
		`INSERT INTO orders (customer_id, total) VALUES (1, 10.50), (1, 22.00), (2, 3.75)`,
	} {
		if _, err := adminConn.Exec(ctx, stmt); err != nil {
			adminConn.Close(ctx)
			t.Fatalf("ddl %q: %v", stmt, err)
		}
	}
	adminConn.Close(ctx)

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

	// A readonly grant on waypoint_test through the "console" listener. The
	// console must reflect exactly this: readable everywhere, writable
	// nowhere.
	capRule := auth.CapRule{
		Limits: &auth.LimitsCap{MaxConns: 10},
		Backends: map[string]auth.BackendCap{
			"console": {
				PG: &auth.PGCap{
					Databases: map[string]auth.DBPermissions{
						"waypoint_test": {
							Permissions: []string{"readonly"},
							Schemas:     []string{"public"},
						},
						"analytics": {
							Permissions: []string{"readonly"},
							Schemas:     []string{"public"},
						},
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

	stateDir := filepath.Join(t.TempDir(), "wp-state")
	os.MkdirAll(stateDir, 0755)

	configContent := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-web-e2e"
control_url = "%s"
state_dir = "%s"
ephemeral = true

[redis]
address = "%s"
key_prefix = "e2e-web:"

[[listeners]]
name = "console"
listen = ":8080"
mode = "web"
backend = "%s"
# The mock control plane cannot issue *.ts.net certificates, so this test
# exercises the console over plain HTTP.
tls_mode = "off"

[listeners.postgres]
admin_user = "admin"
admin_password = "adminpass"
admin_database = "waypoint_test"
user_prefix = "wp_"

[listeners.web]
databases = ["waypoint_test", "analytics"]
max_rows = 2
statement_timeout = "20s"
`, controlURL, stateDir, rdb.Options().Addr, pgBackend)

	configPath := filepath.Join(t.TempDir(), "waypoint.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

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

	// --- Client node: the "browser" ---
	clientDir := filepath.Join(t.TempDir(), "client")
	os.MkdirAll(clientDir, 0755)

	clientNode := &tsnet.Server{
		Dir:        clientDir,
		ControlURL: controlURL,
		Hostname:   "e2e-browser",
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

	var waypointIP string
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st, err := clientLC.Status(ctx)
		if err != nil {
			t.Fatalf("client status: %v", err)
		}
		for _, peer := range st.Peer {
			if peer.HostName == "waypoint-web-e2e" && len(peer.TailscaleIPs) > 0 {
				waypointIP = peer.TailscaleIPs[0].String()
			}
		}
		if waypointIP != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if waypointIP == "" {
		t.Fatal("timed out waiting for waypoint-web-e2e peer")
	}

	// An HTTP client whose transport dials over the tailnet, so every
	// request arrives with the client node's real Tailscale source address.
	base := "http://" + net.JoinHostPort(waypointIP, "8080")
	httpClient := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return clientNode.Dial(ctx, network, addr)
			},
		},
	}

	get := func(t *testing.T, path string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return res
	}

	post := func(t *testing.T, path string, body any, headers map[string]string) *http.Response {
		t.Helper()
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return res
	}

	// Wait for the console to accept connections.
	readyDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(readyDeadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/session", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := httpClient.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Run("session reports the real tailnet identity", func(t *testing.T) {
		res := get(t, "/api/v1/session")
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("status %d: %s", res.StatusCode, b)
		}
		var sess struct {
			User     string   `json:"user"`
			Node     string   `json:"node"`
			Listener string   `json:"listener"`
			Presets  []string `json:"presets"`
			MaxRows  int      `json:"maxRows"`
		}
		if err := json.NewDecoder(res.Body).Decode(&sess); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// The identity came from WhoIs, not from a stub.
		if sess.User == "" {
			t.Error("no login name resolved from WhoIs")
		}
		if sess.Node != "e2e-browser" {
			t.Errorf("node = %q, want e2e-browser", sess.Node)
		}
		if sess.Listener != "console" {
			t.Errorf("listener = %q", sess.Listener)
		}
		// Presets come from the capability grant set on the control plane.
		if len(sess.Presets) != 1 || sess.Presets[0] != "readonly" {
			t.Errorf("presets = %v, want [readonly]", sess.Presets)
		}
		if sess.MaxRows != 2 {
			t.Errorf("maxRows = %d, want 2 from config", sess.MaxRows)
		}
	})

	t.Run("index page is served with a strict CSP", func(t *testing.T) {
		res := get(t, "/")
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status %d", res.StatusCode)
		}
		csp := res.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") {
			t.Errorf("script-src not locked down: %q", csp)
		}
		if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("script-src must not allow inline: %q", csp)
		}
		if res.Header.Get("X-Frame-Options") != "DENY" {
			t.Error("missing X-Frame-Options")
		}
		body, _ := io.ReadAll(res.Body)
		if !bytes.Contains(body, []byte("Waypoint Console")) {
			t.Error("index.html did not render")
		}
	})

	t.Run("schema reflects the grant", func(t *testing.T) {
		res := get(t, "/api/v1/schema?database=waypoint_test")
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("status %d: %s", res.StatusCode, b)
		}
		var cat struct {
			Tables []struct {
				Name   string `json:"name"`
				Select bool   `json:"select"`
				Insert bool   `json:"insert"`
				Update bool   `json:"update"`
			} `json:"tables"`
			ForeignKeys []struct {
				SrcTable string `json:"srcTable"`
				TgtTable string `json:"tgtTable"`
			} `json:"foreignKeys"`
		}
		if err := json.NewDecoder(res.Body).Decode(&cat); err != nil {
			t.Fatalf("decode: %v", err)
		}

		seen := map[string]bool{}
		for _, tb := range cat.Tables {
			seen[tb.Name] = true
			if !tb.Select {
				t.Errorf("%s should be selectable under a readonly grant", tb.Name)
			}
			// The grant is readonly, so provisioning must not have handed
			// out write privileges.
			if tb.Insert || tb.Update {
				t.Errorf("%s is writable under a readonly grant: %+v", tb.Name, tb)
			}
		}
		for _, want := range []string{"customers", "orders", "shipments"} {
			if !seen[want] {
				t.Errorf("table %q missing from catalog", want)
			}
		}
		if len(cat.ForeignKeys) < 2 {
			t.Errorf("expected the FK graph, got %+v", cat.ForeignKeys)
		}
	})

	t.Run("completion offers a foreign-key join", func(t *testing.T) {
		sql := "SELECT * FROM orders o JOIN "
		res := post(t, "/api/v1/complete", map[string]any{
			"database": "waypoint_test", "sql": sql, "cursorPos": len(sql),
		}, nil)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("status %d: %s", res.StatusCode, b)
		}
		var out struct {
			Options []struct {
				Label string `json:"label"`
				Apply string `json:"apply"`
			} `json:"options"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, o := range out.Options {
			if o.Label == "customers" {
				want := "customers ${c} ON o.customer_id = ${c}.id"
				if o.Apply != want {
					t.Errorf("apply = %q, want %q", o.Apply, want)
				}
				return
			}
		}
		t.Errorf("customers not offered as a join target: %+v", out.Options)
	})

	t.Run("diagnostics warn about a write the grant forbids", func(t *testing.T) {
		res := post(t, "/api/v1/diagnostics", map[string]any{
			"database": "waypoint_test",
			"sql":      "UPDATE customers SET name = 'x' WHERE id = 1",
		}, nil)
		defer res.Body.Close()
		var out struct {
			Diagnostics []struct {
				Severity string `json:"severity"`
				Message  string `json:"message"`
				Source   string `json:"source"`
			} `json:"diagnostics"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, d := range out.Diagnostics {
			if d.Source == "permission" && strings.Contains(d.Message, "UPDATE") {
				return
			}
		}
		t.Errorf("no permission warning for a readonly grant: %+v", out.Diagnostics)
	})

	t.Run("query streams the pid before rows and honours the row cap", func(t *testing.T) {
		res := post(t, "/api/v1/query", map[string]any{
			"database": "waypoint_test",
			"sql":      "SELECT id, total FROM orders ORDER BY id",
		}, nil)
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("status %d: %s", res.StatusCode, b)
		}

		var frames []map[string]any
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var f map[string]any
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				t.Fatalf("decode frame %q: %v", line, err)
			}
			frames = append(frames, f)
		}
		if len(frames) < 3 {
			t.Fatalf("expected begin/columns/rows/end, got %+v", frames)
		}
		if frames[0]["type"] != "begin" {
			t.Fatalf("first frame = %v, want begin", frames[0]["type"])
		}
		if pid, _ := frames[0]["pid"].(float64); pid <= 0 {
			t.Errorf("no backend pid in the first frame: %+v", frames[0])
		}

		var end map[string]any
		rows := 0
		for _, f := range frames {
			switch f["type"] {
			case "rows":
				rows += len(f["rows"].([]any))
			case "end":
				end = f
			}
		}
		// max_rows = 2 in the config, and there are 3 orders.
		if rows != 2 {
			t.Errorf("streamed %d rows, want the configured cap of 2", rows)
		}
		if end == nil || end["truncated"] != true {
			t.Errorf("expected truncated=true, got %+v", end)
		}
	})

	t.Run("a forbidden write is refused by postgres", func(t *testing.T) {
		res := post(t, "/api/v1/query", map[string]any{
			"database": "waypoint_test",
			"sql":      "UPDATE customers SET name = 'x' WHERE id = 1",
		}, nil)
		defer res.Body.Close()

		var errFrame map[string]any
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			var f map[string]any
			if json.Unmarshal(scanner.Bytes(), &f) == nil && f["type"] == "error" {
				errFrame = f
			}
		}
		if errFrame == nil {
			t.Fatal("the database accepted a write under a readonly grant")
		}
		if errFrame["code"] != "42501" {
			t.Errorf("code = %v, want 42501", errFrame["code"])
		}
	})

	t.Run("a database outside the grant is refused", func(t *testing.T) {
		res := post(t, "/api/v1/query", map[string]any{
			"database": "postgres",
			"sql":      "SELECT 1",
		}, nil)
		defer res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", res.StatusCode)
		}
	})

	t.Run("cross-site requests are rejected", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			headers map[string]string
		}{
			{"fetch metadata says cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}},
			{"foreign origin", map[string]string{"Sec-Fetch-Site": "", "Origin": "https://evil.example"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res := post(t, "/api/v1/query", map[string]any{
					"database": "waypoint_test", "sql": "SELECT 1",
				}, tc.headers)
				defer res.Body.Close()
				if res.StatusCode != http.StatusForbidden {
					t.Errorf("status = %d, want 403", res.StatusCode)
				}
			})
		}
	})

	t.Run("a second database is fully usable", func(t *testing.T) {
		// The regression this guards: provisioning used to apply its GRANTs
		// over a connection to admin_database, so a role for any other
		// database had its privileges in the wrong one and every query was
		// refused with 42501.
		res := get(t, "/api/v1/schema?database=analytics")
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("schema for analytics: status %d: %s", res.StatusCode, b)
		}
		var cat struct {
			Tables []struct {
				Name   string `json:"name"`
				Select bool   `json:"select"`
			} `json:"tables"`
		}
		if err := json.NewDecoder(res.Body).Decode(&cat); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var found bool
		for _, tb := range cat.Tables {
			if tb.Name == "events" {
				found = true
				if !tb.Select {
					t.Error("events is visible but not selectable in analytics")
				}
			}
			// The other database's relations must not leak into this one.
			if tb.Name == "customers" || tb.Name == "orders" {
				t.Errorf("analytics catalog contains %q from waypoint_test", tb.Name)
			}
		}
		if !found {
			t.Fatalf("events not in the analytics catalog; got %+v", cat.Tables)
		}

		// And the query actually runs.
		qres := post(t, "/api/v1/query", map[string]any{
			"database": "analytics", "sql": "SELECT count(*) FROM events",
		}, nil)
		defer qres.Body.Close()
		var rows int
		var failure string
		scanner := bufio.NewScanner(qres.Body)
		for scanner.Scan() {
			var f map[string]any
			if json.Unmarshal(scanner.Bytes(), &f) != nil {
				continue
			}
			if f["type"] == "error" {
				failure = fmt.Sprint(f["code"], " ", f["message"])
			}
			if f["type"] == "rows" {
				rows++
			}
		}
		if failure != "" {
			t.Fatalf("query against analytics failed: %s", failure)
		}
		if rows == 0 {
			t.Error("query against analytics returned no rows")
		}
	})

	t.Run("each database gets its own role", func(t *testing.T) {
		roleFor := func(db string) string {
			res := post(t, "/api/v1/query", map[string]any{
				"database": db, "sql": "SELECT current_user",
			}, nil)
			defer res.Body.Close()
			scanner := bufio.NewScanner(res.Body)
			for scanner.Scan() {
				var f map[string]any
				if json.Unmarshal(scanner.Bytes(), &f) != nil {
					continue
				}
				if f["type"] == "rows" {
					if r, ok := f["rows"].([]any); ok && len(r) > 0 {
						if c, ok := r[0].([]any); ok && len(c) > 0 {
							return fmt.Sprint(c[0])
						}
					}
				}
			}
			return ""
		}
		a, b := roleFor("waypoint_test"), roleFor("analytics")
		if a == "" || b == "" {
			t.Fatalf("no role reported: %q %q", a, b)
		}
		if a == b {
			t.Errorf("both databases resolved to the role %q; their grants would collide", a)
		}
	})

	t.Run("revoking the grant takes effect on the next request", func(t *testing.T) {
		// This is the property the stateless design exists for: there is no
		// session to outlive the grant that created it.
		control.SetGlobalAppCaps(tailcfg.PeerCapMap{})

		revoked := time.Now().Add(30 * time.Second)
		for time.Now().Before(revoked) {
			res := get(t, "/api/v1/session")
			code := res.StatusCode
			res.Body.Close()
			if code == http.StatusForbidden {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Error("console still authorized after the capability grant was removed")
	})

	// --- Shutdown ---
	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}

// TestE2E_WebConsole_MatchesWireProtocolAuthority is the console's central
// security property: it must not be a privilege escalation path.
//
// Anything the console can do to the database, a psql session through the
// postgres listener must be able to do too — and, more importantly, anything
// the wire protocol refuses the console must refuse identically. The test
// makes that comparison directly: one waypoint process serves a postgres
// listener and a web listener over the same backend with the same admin
// credentials, the same user prefix, and identical capability grants, and
// every statement in the corpus below is executed through both paths and the
// outcomes compared.
//
// The two paths deliberately resolve to *different* PG roles — the listener
// name is part of every role name — so this is not equivalence by shared
// identity. Each listener provisions its own role from its own grant, and the
// test asserts the outcomes match anyway. That is the stronger property: it
// holds because the grants are equal, not because the roles happen to be.
func TestE2E_WebConsole_MatchesWireProtocolAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	pgConnStr, pgBackend := testutil.PostgresBackend(t)

	adminConn, err := pgx.Connect(ctx, pgConnStr)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS orders, customers CASCADE`,
		`DROP TABLE IF EXISTS wp_evil`,
		`DROP ROLE IF EXISTS wp_hacker`,
		`CREATE TABLE customers (id bigserial PRIMARY KEY, email text, name text)`,
		`CREATE TABLE orders (id bigserial PRIMARY KEY,
		    customer_id bigint NOT NULL REFERENCES customers(id), total numeric)`,
		`INSERT INTO customers (email, name) VALUES ('a@example.com','Ann')`,
		`INSERT INTO orders (customer_id, total) VALUES (1, 10.50)`,
	} {
		if _, err := adminConn.Exec(ctx, stmt); err != nil {
			adminConn.Close(ctx)
			t.Fatalf("ddl %q: %v", stmt, err)
		}
	}
	adminConn.Close(ctx)

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

	// Identical grants for both listeners. Any difference in what the two
	// paths allow therefore comes from the code, not from the policy.
	pgCap := &auth.PGCap{
		Databases: map[string]auth.DBPermissions{
			"waypoint_test": {Permissions: []string{"readonly"}, Schemas: []string{"public"}},
		},
	}
	capRule := auth.CapRule{
		Limits: &auth.LimitsCap{MaxConns: 20},
		Backends: map[string]auth.BackendCap{
			"pg-equiv":  {PG: pgCap},
			"web-equiv": {PG: pgCap},
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
	stateDir := filepath.Join(t.TempDir(), "wp-state")
	os.MkdirAll(stateDir, 0755)

	// Same backend, same admin user, same user_prefix on both listeners, so
	// both provision the identical role.
	adminBlock := `
[listeners.postgres]
admin_user = "admin"
admin_password = "adminpass"
admin_database = "waypoint_test"
user_prefix = "wp_"
`
	configContent := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-equiv-e2e"
control_url = "%s"
state_dir = "%s"
ephemeral = true

[redis]
address = "%s"
key_prefix = "e2e-equiv:"

[[listeners]]
name = "pg-equiv"
listen = ":5442"
mode = "postgres"
backend = "%s"
tls_mode = "off"
%s
[[listeners]]
name = "web-equiv"
listen = ":8082"
mode = "web"
backend = "%s"
tls_mode = "off"
%s
[listeners.web]
databases = ["waypoint_test"]
max_rows = 100
statement_timeout = "20s"
`, controlURL, stateDir, rdb.Options().Addr, pgBackend, adminBlock, pgBackend, adminBlock)

	configPath := filepath.Join(t.TempDir(), "waypoint.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	var levelVar slog.LevelVar
	levelVar.Set(slog.LevelWarn)
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &levelVar}))
	errCh := make(chan error, 1)
	go func() { errCh <- server.RunServer(runCtx, configPath, lgr, &levelVar, nil) }()

	select {
	case err := <-errCh:
		t.Fatalf("RunServer exited early: %v", err)
	case <-time.After(2 * time.Second):
	}

	clientDir := filepath.Join(t.TempDir(), "client")
	os.MkdirAll(clientDir, 0755)
	clientNode := &tsnet.Server{
		Dir:        clientDir,
		ControlURL: controlURL,
		Hostname:   "equiv-client",
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

	var waypointIP string
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st, err := clientLC.Status(ctx)
		if err != nil {
			t.Fatalf("client status: %v", err)
		}
		for _, peer := range st.Peer {
			if peer.HostName == "waypoint-equiv-e2e" && len(peer.TailscaleIPs) > 0 {
				waypointIP = peer.TailscaleIPs[0].String()
			}
		}
		if waypointIP != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if waypointIP == "" {
		t.Fatal("timed out waiting for the waypoint peer")
	}

	// --- wire path: a pgx client through the postgres listener ---
	wireCfg, err := pgx.ParseConfig(fmt.Sprintf(
		"postgres://ignored:ignored@%s/waypoint_test?sslmode=disable", net.JoinHostPort(waypointIP, "5442")))
	if err != nil {
		t.Fatalf("parse wire config: %v", err)
	}
	wireCfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return clientNode.Dial(ctx, network, addr)
	}

	var wireConn *pgx.Conn
	dialDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(dialDeadline) {
		wireConn, err = pgx.ConnectConfig(ctx, wireCfg)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("wire connect: %v", err)
	}
	wireClosed := false
	closeWire := func() {
		if !wireClosed {
			wireClosed = true
			wireConn.Close(ctx)
		}
	}
	defer closeWire()

	// --- web path ---
	webBase := "http://" + net.JoinHostPort(waypointIP, "8082")
	httpClient := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return clientNode.Dial(ctx, network, addr)
			},
		},
	}

	readyDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(readyDeadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, webBase+"/api/v1/session", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := httpClient.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	runWeb := func(t *testing.T, stmt string) sqlOutcome {
		t.Helper()
		body, err := json.Marshal(map[string]any{"database": "waypoint_test", "sql": stmt})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webBase+"/api/v1/query", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("web query %q: %v", stmt, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return sqlOutcome{Failed: true, Code: fmt.Sprintf("http-%d", res.StatusCode)}
		}

		out := sqlOutcome{}
		scanner := bufio.NewScanner(res.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			var f map[string]any
			if json.Unmarshal(scanner.Bytes(), &f) != nil {
				continue
			}
			switch f["type"] {
			case "error":
				out.Failed = true
				if c, ok := f["code"].(string); ok {
					out.Code = c
				} else {
					out.Code = "unknown"
				}
			case "rows":
				if out.First == "" {
					if rows, ok := f["rows"].([]any); ok && len(rows) > 0 {
						if cells, ok := rows[0].([]any); ok && len(cells) > 0 {
							out.First = fmt.Sprint(cells[0])
						}
					}
				}
			}
		}
		return out
	}

	runWire := func(t *testing.T, stmt string) sqlOutcome {
		t.Helper()
		rows, err := wireConn.Query(ctx, stmt)
		if err != nil {
			return outcomeFromErr(err)
		}
		out := sqlOutcome{}
		for rows.Next() {
			if out.First == "" {
				vals, verr := rows.Values()
				if verr == nil && len(vals) > 0 && vals[0] != nil {
					out.First = fmt.Sprint(vals[0])
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return outcomeFromErr(err)
		}
		return out
	}

	// The corpus. mustFail marks statements that must be refused on both
	// paths — agreement alone is not enough for those, since two paths that
	// both wrongly allowed something would still agree.
	corpus := []struct {
		name     string
		stmt     string
		mustFail bool
		compare  bool // also require the returned value to match
	}{
		{name: "trivial read", stmt: "SELECT 1"},
		{name: "granted table read", stmt: "SELECT count(*) FROM customers"},
		{name: "join read", stmt: "SELECT count(*) FROM orders o JOIN customers c ON o.customer_id = c.id"},
		{name: "information_schema", stmt: "SELECT count(*) FROM information_schema.tables"},

		// Each listener has its own role, so the identity differs by design
		// — that is checked separately below. What must match is the
		// authority those roles carry.
		{name: "current_user", stmt: "SELECT current_user"},
		{name: "session_user", stmt: "SELECT session_user"},
		{name: "is_superuser", stmt: "SELECT current_setting('is_superuser')", compare: true},

		// Writes, under a readonly grant.
		{name: "insert", stmt: "INSERT INTO customers (email, name) VALUES ('x@example.com','X')", mustFail: true},
		{name: "update", stmt: "UPDATE customers SET name = 'x'", mustFail: true},
		{name: "delete", stmt: "DELETE FROM customers", mustFail: true},
		{name: "truncate", stmt: "TRUNCATE customers", mustFail: true},

		// DDL.
		{name: "create table", stmt: "CREATE TABLE wp_evil (i int)", mustFail: true},
		{name: "drop table", stmt: "DROP TABLE customers", mustFail: true},
		{name: "alter table", stmt: "ALTER TABLE customers ADD COLUMN x int", mustFail: true},

		// Privilege escalation.
		{name: "create role", stmt: "CREATE ROLE wp_hacker LOGIN PASSWORD 'p'", mustFail: true},
		{name: "self grant superuser", stmt: "ALTER ROLE CURRENT_USER SUPERUSER", mustFail: true},
		{name: "set role to admin", stmt: "SET ROLE admin", mustFail: true},

		// Reading the authentication catalog.
		{name: "pg_authid", stmt: "SELECT count(*) FROM pg_authid", mustFail: true},
		{name: "pg_shadow", stmt: "SELECT count(*) FROM pg_shadow", mustFail: true},

		// Server-side file and extension access.
		{name: "read server file", stmt: "SELECT pg_read_file('/etc/passwd')", mustFail: true},
		{name: "copy to file", stmt: "COPY customers TO '/tmp/wp_leak'", mustFail: true},
		{name: "create extension", stmt: "CREATE EXTENSION IF NOT EXISTS pg_stat_statements", mustFail: true},
		{name: "large object", stmt: "SELECT lo_import('/etc/passwd')", mustFail: true},
	}

	for _, tc := range corpus {
		t.Run(tc.name, func(t *testing.T) {
			wire := runWire(t, tc.stmt)
			web := runWeb(t, tc.stmt)

			if wire.Failed != web.Failed {
				t.Fatalf("paths disagree on %q:\n  wire: %s\n  web:  %s", tc.stmt, wire, web)
			}
			if wire.Failed && wire.Code != web.Code {
				t.Errorf("paths failed differently on %q:\n  wire: %s\n  web:  %s", tc.stmt, wire, web)
			}
			if tc.mustFail && !web.Failed {
				t.Errorf("%q succeeded through the console; it must be refused", tc.stmt)
			}
			if tc.mustFail && !wire.Failed {
				t.Errorf("%q succeeded through the wire protocol; the corpus expectation is wrong", tc.stmt)
			}
			if tc.compare && wire.First != web.First {
				t.Errorf("paths returned different values for %q:\n  wire: %q\n  web:  %q",
					tc.stmt, wire.First, web.First)
			}
		})
	}

	t.Run("a self-grant confers nothing on either path", func(t *testing.T) {
		// Postgres does not reject a GRANT issued by a role without grant
		// option — it emits a warning and grants nothing. Both paths
		// therefore report success, so the assertion that matters is that
		// the privilege was not actually conferred.
		stmt := "GRANT ALL ON customers TO CURRENT_USER"
		wire := runWire(t, stmt)
		web := runWeb(t, stmt)
		if wire.Failed != web.Failed {
			t.Fatalf("paths disagree on %q:\n  wire: %s\n  web:  %s", stmt, wire, web)
		}

		// The write must still be refused afterwards, through both paths.
		if out := runWeb(t, "UPDATE customers SET name = 'x'"); !out.Failed {
			t.Error("the console could write after a self-grant")
		}
		if out := runWire(t, "UPDATE customers SET name = 'x'"); !out.Failed {
			t.Error("the wire path could write after a self-grant")
		}
	})

	t.Run("each listener runs as its own non-admin role", func(t *testing.T) {
		wire := runWire(t, "SELECT current_user")
		web := runWeb(t, "SELECT current_user")
		if wire.First == "" || web.First == "" {
			t.Fatalf("no role reported: wire=%q web=%q", wire.First, web.First)
		}
		// Distinct, because the listener name is part of the role name. This
		// is what lets the two listeners carry different grants without
		// clobbering each other, even under a shared user_prefix.
		if wire.First == web.First {
			t.Errorf("both listeners share the role %q; differing grants would collide", wire.First)
		}
		if !strings.HasPrefix(wire.First, "wp_pg_equiv_") {
			t.Errorf("wire role %q does not name its listener", wire.First)
		}
		if !strings.HasPrefix(web.First, "wp_web_equiv_") {
			t.Errorf("console role %q does not name its listener", web.First)
		}
		// Provisioned roles, never the admin account the provisioner holds.
		for _, role := range []string{wire.First, web.First} {
			if role == "admin" || role == "postgres" {
				t.Errorf("running as the admin account %q", role)
			}
			if !strings.HasPrefix(role, "wp_") {
				t.Errorf("role %q is not a provisioned wp_ role", role)
			}
		}
	})

	t.Run("wire reconnects do not disturb the console", func(t *testing.T) {
		// Each listener owns its own role now, so a wire reconnect rotates a
		// password the console never uses. Before the listener became part of
		// the role name the two shared one role and this rotation invalidated
		// the console's pooled credential on every reconnect.
		second, err := pgx.ConnectConfig(ctx, wireCfg)
		if err != nil {
			t.Fatalf("second wire connect: %v", err)
		}
		defer second.Close(ctx)

		if out := runWeb(t, "SELECT 1"); out.Failed {
			t.Errorf("console failed after a wire reconnect: %s", out)
		}
	})

	// --- the endpoints that read the catalog rather than run a statement ---
	//
	// /api/v1/query is not the only way the console touches the database.
	// The catalog, completion, and diagnostics endpoints all read schema
	// information, and each has to expose exactly what the same role would
	// see through psql — no more.

	webGet := func(t *testing.T, path string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, webBase+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return res
	}

	webPost := func(t *testing.T, path string, body any) *http.Response {
		t.Helper()
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webBase+path, bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return res
	}

	t.Run("schema endpoint shows exactly what the role can see", func(t *testing.T) {
		res := webGet(t, "/api/v1/schema?database=waypoint_test")
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status %d", res.StatusCode)
		}
		var cat struct {
			Tables []struct {
				Schema string `json:"schema"`
				Name   string `json:"name"`
			} `json:"tables"`
		}
		if err := json.NewDecoder(res.Body).Decode(&cat); err != nil {
			t.Fatalf("decode: %v", err)
		}
		fromWeb := map[string]bool{}
		for _, tb := range cat.Tables {
			fromWeb[tb.Schema+"."+tb.Name] = true
		}

		// The same question, asked through the wire protocol by the same role.
		rows, err := wireConn.Query(ctx, `
			SELECT table_schema, table_name FROM information_schema.tables
			WHERE table_schema NOT IN ('pg_catalog','information_schema')
			  AND table_type IN ('BASE TABLE','VIEW')`)
		if err != nil {
			t.Fatalf("wire introspection: %v", err)
		}
		fromWire := map[string]bool{}
		for rows.Next() {
			var sch, name string
			if err := rows.Scan(&sch, &name); err != nil {
				rows.Close()
				t.Fatalf("scan: %v", err)
			}
			fromWire[sch+"."+name] = true
		}
		rows.Close()

		if !reflect.DeepEqual(fromWeb, fromWire) {
			t.Errorf("catalog differs between paths:\n  web:  %v\n  wire: %v", fromWeb, fromWire)
		}
		for name := range fromWeb {
			if strings.HasPrefix(name, "pg_catalog.") || strings.HasPrefix(name, "information_schema.") {
				t.Errorf("console exposed system relation %q", name)
			}
		}
	})

	t.Run("columns endpoint refuses relations outside the grant", func(t *testing.T) {
		// pg_catalog is not privilege-filtered, so this is the request that
		// would leak if the endpoint trusted its own parameters instead of
		// checking them against the permission-scoped catalog first.
		for _, target := range []struct{ schema, table string }{
			{"pg_catalog", "pg_authid"},
			{"pg_catalog", "pg_shadow"},
			{"", "pg_authid"},
			{"information_schema", "role_table_grants"},
		} {
			res := webPost(t, "/api/v1/columns", map[string]any{
				"database": "waypoint_test", "schema": target.schema, "table": target.table,
			})
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				t.Errorf("columns endpoint exposed %s.%s: %s", target.schema, target.table, body)
			}
		}

		// And it still works for a relation the grant does cover.
		res := webPost(t, "/api/v1/columns", map[string]any{
			"database": "waypoint_test", "schema": "public", "table": "customers",
		})
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Errorf("columns endpoint refused a granted relation: status %d", res.StatusCode)
		}
	})

	t.Run("completion never names a relation outside the grant", func(t *testing.T) {
		for _, sql := range []string{
			"SELECT * FROM pg_",
			"SELECT * FROM pg_authid a JOIN ",
			"SELECT a. FROM pg_authid a",
		} {
			res := webPost(t, "/api/v1/complete", map[string]any{
				"database": "waypoint_test", "sql": sql, "cursorPos": len(sql),
			})
			var out struct {
				Options []struct {
					Label        string `json:"label"`
					DisplayLabel string `json:"displayLabel"`
					Info         string `json:"info"`
				} `json:"options"`
			}
			if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
				res.Body.Close()
				t.Fatalf("decode: %v", err)
			}
			res.Body.Close()
			for _, o := range out.Options {
				for _, field := range []string{o.Label, o.DisplayLabel, o.Info} {
					if strings.Contains(field, "pg_authid") || strings.Contains(field, "rolpassword") {
						t.Errorf("completion for %q leaked %q", sql, field)
					}
				}
			}
		}
	})

	t.Run("cancel refuses a backend belonging to another role", func(t *testing.T) {
		// A connection made directly to Postgres as the admin account, which
		// the console must not be able to signal.
		other, err := pgx.Connect(ctx, pgConnStr)
		if err != nil {
			t.Fatalf("admin connect: %v", err)
		}
		defer other.Close(ctx)

		var otherPID int32
		if err := other.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&otherPID); err != nil {
			t.Fatalf("pid: %v", err)
		}

		res := webPost(t, "/api/v1/cancel", map[string]any{
			"database": "waypoint_test", "pid": otherPID,
		})
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode == http.StatusOK {
			t.Errorf("console cancelled a backend owned by another role: %s", body)
		}

		// The other connection must still be usable.
		var one int
		if err := other.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
			t.Errorf("the other role's connection was disturbed: %v", err)
		}
	})

	t.Run("a database outside the listener menu is refused", func(t *testing.T) {
		for _, db := range []string{"postgres", "template1", ""} {
			if db == "" {
				continue
			}
			res := webPost(t, "/api/v1/query", map[string]any{"database": db, "sql": "SELECT 1"})
			res.Body.Close()
			if res.StatusCode != http.StatusForbidden {
				t.Errorf("database %q: status %d, want 403", db, res.StatusCode)
			}
		}
	})

	// Close the wire connection before cancelling: shutdown drains active
	// connections, and a live one would hold it open past the deadline.
	closeWire()

	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}

// sqlOutcome is what a statement did, reduced to what can be compared across
// the two paths.
type sqlOutcome struct {
	Failed bool
	Code   string
	First  string
}

func (o sqlOutcome) String() string {
	if o.Failed {
		return "error " + o.Code
	}
	if o.First != "" {
		return "ok (" + o.First + ")"
	}
	return "ok"
}

func outcomeFromErr(err error) sqlOutcome {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return sqlOutcome{Failed: true, Code: pe.Code}
	}
	return sqlOutcome{Failed: true, Code: "unknown"}
}

// TestE2E_WebConsole_GrantsAreIndependentPerListener shows that a capability
// grant can give the console different access from the wire protocol.
//
// Grants are keyed by listener name, so "console" and "pg-main" are separate
// keys carrying separate permissions. This test gives the postgres listener
// readwrite and the web listener readonly and checks that each honours its
// own grant.
//
// Both listeners deliberately use the *same* user_prefix. Role names include
// the listener, so they still resolve to distinct roles and their grants
// cannot clobber one another — no per-listener prefix juggling required.
func TestE2E_WebConsole_GrantsAreIndependentPerListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	pgConnStr, pgBackend := testutil.PostgresBackend(t)
	adminConn, err := pgx.Connect(ctx, pgConnStr)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS notes CASCADE`,
		`CREATE TABLE notes (id bigserial PRIMARY KEY, body text)`,
		`INSERT INTO notes (body) VALUES ('seed')`,
	} {
		if _, err := adminConn.Exec(ctx, stmt); err != nil {
			adminConn.Close(ctx)
			t.Fatalf("ddl %q: %v", stmt, err)
		}
	}
	adminConn.Close(ctx)

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

	// Different permissions for the two listeners, in one grant.
	capRule := auth.CapRule{
		Limits: &auth.LimitsCap{MaxConns: 20},
		Backends: map[string]auth.BackendCap{
			"pg-rw": {PG: &auth.PGCap{Databases: map[string]auth.DBPermissions{
				"waypoint_test": {Permissions: []string{"readwrite"}, Schemas: []string{"public"}},
			}}},
			"web-ro": {PG: &auth.PGCap{Databases: map[string]auth.DBPermissions{
				"waypoint_test": {Permissions: []string{"readonly"}, Schemas: []string{"public"}},
			}}},
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
	stateDir := filepath.Join(t.TempDir(), "wp-state")
	os.MkdirAll(stateDir, 0755)

	configContent := fmt.Sprintf(`
[tailscale]
hostname = "waypoint-split-e2e"
control_url = "%s"
state_dir = "%s"
ephemeral = true

[redis]
address = "%s"
key_prefix = "e2e-split:"

[[listeners]]
name = "pg-rw"
listen = ":5443"
mode = "postgres"
backend = "%s"
tls_mode = "off"

[listeners.postgres]
admin_user = "admin"
admin_password = "adminpass"
admin_database = "waypoint_test"
user_prefix = "wp_"

[[listeners]]
name = "web-ro"
listen = ":8083"
mode = "web"
backend = "%s"
tls_mode = "off"

[listeners.postgres]
admin_user = "admin"
admin_password = "adminpass"
admin_database = "waypoint_test"
user_prefix = "wp_"

[listeners.web]
databases = ["waypoint_test"]
max_rows = 100
`, controlURL, stateDir, rdb.Options().Addr, pgBackend, pgBackend)

	configPath := filepath.Join(t.TempDir(), "waypoint.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	var levelVar slog.LevelVar
	levelVar.Set(slog.LevelWarn)
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &levelVar}))
	errCh := make(chan error, 1)
	go func() { errCh <- server.RunServer(runCtx, configPath, lgr, &levelVar, nil) }()

	select {
	case err := <-errCh:
		t.Fatalf("RunServer exited early: %v", err)
	case <-time.After(2 * time.Second):
	}

	clientNode := &tsnet.Server{
		Dir:        filepath.Join(t.TempDir(), "client"),
		ControlURL: controlURL,
		Hostname:   "split-client",
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

	var waypointIP string
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st, err := clientLC.Status(ctx)
		if err != nil {
			t.Fatalf("status: %v", err)
		}
		for _, peer := range st.Peer {
			if peer.HostName == "waypoint-split-e2e" && len(peer.TailscaleIPs) > 0 {
				waypointIP = peer.TailscaleIPs[0].String()
			}
		}
		if waypointIP != "" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if waypointIP == "" {
		t.Fatal("timed out waiting for the waypoint peer")
	}

	wireCfg, err := pgx.ParseConfig(fmt.Sprintf(
		"postgres://x:x@%s/waypoint_test?sslmode=disable", net.JoinHostPort(waypointIP, "5443")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wireCfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return clientNode.Dial(ctx, network, addr)
	}
	var wireConn *pgx.Conn
	dialDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(dialDeadline) {
		wireConn, err = pgx.ConnectConfig(ctx, wireCfg)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("wire connect: %v", err)
	}

	webBase := "http://" + net.JoinHostPort(waypointIP, "8083")
	httpClient := &http.Client{
		Timeout: 45 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientNode.Dial(ctx, network, addr)
		}},
	}
	readyDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(readyDeadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, webBase+"/api/v1/session", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := httpClient.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	webQuery := func(t *testing.T, stmt string) sqlOutcome {
		t.Helper()
		buf, _ := json.Marshal(map[string]any{"database": "waypoint_test", "sql": stmt})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webBase+"/api/v1/query", bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("web query: %v", err)
		}
		defer res.Body.Close()
		out := sqlOutcome{}
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			var f map[string]any
			if json.Unmarshal(scanner.Bytes(), &f) != nil {
				continue
			}
			if f["type"] == "error" {
				out.Failed = true
				if c, ok := f["code"].(string); ok {
					out.Code = c
				}
			}
			if f["type"] == "rows" && out.First == "" {
				if rows, ok := f["rows"].([]any); ok && len(rows) > 0 {
					if cells, ok := rows[0].([]any); ok && len(cells) > 0 {
						out.First = fmt.Sprint(cells[0])
					}
				}
			}
		}
		return out
	}

	t.Run("the wire listener's readwrite grant allows a write", func(t *testing.T) {
		if _, err := wireConn.Exec(ctx, "INSERT INTO notes (body) VALUES ('from-wire')"); err != nil {
			t.Errorf("readwrite grant did not permit an insert: %v", err)
		}
	})

	t.Run("the web listener's readonly grant refuses the same write", func(t *testing.T) {
		out := webQuery(t, "INSERT INTO notes (body) VALUES ('from-web')")
		if !out.Failed {
			t.Fatal("the console performed a write its own grant does not allow")
		}
		if out.Code != "42501" {
			t.Errorf("code = %q, want 42501 insufficient privilege", out.Code)
		}
	})

	t.Run("the console can still read", func(t *testing.T) {
		if out := webQuery(t, "SELECT count(*) FROM notes"); out.Failed {
			t.Errorf("readonly grant did not permit a read: %s", out)
		}
	})

	t.Run("distinct roles despite a shared user_prefix", func(t *testing.T) {
		var wireRole string
		if err := wireConn.QueryRow(ctx, "SELECT current_user").Scan(&wireRole); err != nil {
			t.Fatalf("wire current_user: %v", err)
		}
		webRole := webQuery(t, "SELECT current_user").First
		if wireRole == webRole {
			t.Fatalf("both listeners resolved to %q; their differing grants would clobber each other", wireRole)
		}
		// The listener leads the name, so a role is attributable to its
		// listener at a glance in pg_stat_activity.
		if !strings.HasPrefix(wireRole, "wp_pg_rw_") {
			t.Errorf("wire role %q does not lead with its listener", wireRole)
		}
		if !strings.HasPrefix(webRole, "wp_web_ro_") {
			t.Errorf("console role %q does not lead with its listener", webRole)
		}
	})

	wireConn.Close(ctx)
	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunServer: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}
