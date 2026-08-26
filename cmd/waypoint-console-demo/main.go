//go:build demo

// Command waypoint-console-demo runs the web console against a mock Tailscale
// control plane, so the console can be tried on a machine with no tailnet.
//
// It is not part of any release build — the `demo` build tag keeps the test
// control plane out of the shipped binary's dependency graph. Run it with:
//
//	go run -tags demo ./cmd/waypoint-console-demo
//
// What it does:
//
//   - starts an in-process Tailscale control plane and DERP server
//   - grants the waypoint capability the flags describe
//   - runs the real waypoint server with a mode = "web" listener
//   - joins the mock tailnet as a second node, standing in for the browser
//   - reverse-proxies 127.0.0.1 to the console over that mock tailnet
//
// The last step is what makes it usable from a normal browser. Requests still
// arrive at the console from a real Tailscale peer address and are still
// authorized by a real WhoIs against a real capability grant — the identity
// path is the production one, only the control plane is fake.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/server"
)

func main() {
	var (
		pgBackend = flag.String("backend", "127.0.0.1:55432", "postgres backend host:port")
		pgUser    = flag.String("admin-user", "postgres", "postgres admin user")
		pgPass    = flag.String("admin-password", "demopw", "postgres admin password")
		database  = flag.String("database", "appdb", "comma-separated databases to expose; the first is the default")
		redisAddr = flag.String("redis", "127.0.0.1:56379", "redis address")
		preset    = flag.String("preset", "readwrite", "capability preset: readonly, readwrite, or admin")
		localAddr = flag.String("addr", "127.0.0.1:8080", "local address to serve the console on")
		maxRows   = flag.Int("max-rows", 500, "row cap per statement")
		verbose   = flag.Bool("v", false, "verbose waypoint logs")
	)
	flag.Parse()

	databases := strings.Split(*database, ",")
	for i := range databases {
		databases[i] = strings.TrimSpace(databases[i])
	}

	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelDebug
	}
	var levelVar slog.LevelVar
	levelVar.Set(logLevel)
	lgr := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &levelVar}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The mock control plane and DERP both live in this process.
	netns.SetEnabled(false)
	defer netns.SetEnabled(true)

	shim := &testShim{}
	defer shim.runCleanups()
	derpMap := integration.RunDERPAndSTUN(shim, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap:        derpMap,
		DNSConfig:      &tailcfg.DNSConfig{Proxied: true},
		MagicDNSDomain: "tail-scale.ts.net",
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	defer control.HTTPTestServer.Close()

	// The capability grant. This is the same shape a real tailnet ACL uses;
	// change -preset to see the console's permission handling shift.
	grantedDBs := map[string]auth.DBPermissions{}
	for _, db := range databases {
		grantedDBs[db] = auth.DBPermissions{
			Permissions: []string{*preset},
			Schemas:     []string{"public"},
		}
	}
	capRule := auth.CapRule{
		Limits: &auth.LimitsCap{MaxConns: 20},
		Backends: map[string]auth.BackendCap{
			"console": {
				PG: &auth.PGCap{Databases: grantedDBs},
			},
		},
	}
	capJSON, err := json.Marshal(capRule)
	if err != nil {
		fatal("marshal capability grant: %v", err)
	}
	control.SetGlobalAppCaps(tailcfg.PeerCapMap{
		tailcfg.PeerCapability(auth.WaypointCap): {tailcfg.RawMessage(capJSON)},
	})

	tmp, err := os.MkdirTemp("", "waypoint-console-demo")
	if err != nil {
		fatal("temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	configPath := filepath.Join(tmp, "waypoint.toml")
	configBody := fmt.Sprintf(`
log_level = "debug"

[tailscale]
hostname = "waypoint-console-demo"
control_url = %q
state_dir = %q
ephemeral = true

[redis]
address = %q
key_prefix = "console-demo:"

[revalidation]
interval = "1m"

[[listeners]]
name = "console"
listen = ":8080"
mode = "web"
backend = %q
tls_mode = "off"

[listeners.postgres]
admin_user = %q
admin_password = %q
admin_database = %q
user_prefix = "wp_"
user_ttl = "1h"

[listeners.web]
databases = [%s]
max_rows = %d
statement_timeout = "30s"

[listeners.query_log]
level = "normalized"
max_level = "full"
`, control.HTTPTestServer.URL, filepath.Join(tmp, "state"),
		*redisAddr, *pgBackend, *pgUser, *pgPass, databases[0], quotedList(databases), *maxRows)

	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		fatal("write config: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- server.RunServer(ctx, configPath, lgr, &levelVar, nil) }()

	select {
	case err := <-errCh:
		fatal("waypoint exited during startup: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}

	// A second node on the mock tailnet, standing in for the browser's
	// machine. Every proxied request carries this node's Tailscale address,
	// so WhoIs on the console side resolves a real peer.
	clientNode := &tsnet.Server{
		Dir:        filepath.Join(tmp, "client"),
		ControlURL: control.HTTPTestServer.URL,
		Hostname:   "console-browser",
		Store:      new(mem.Store),
		Ephemeral:  true,
		Logf:       func(string, ...any) {},
	}
	defer clientNode.Close()

	fmt.Fprintln(os.Stderr, "joining mock tailnet…")
	if _, err := clientNode.Up(ctx); err != nil {
		fatal("client node: %v", err)
	}

	consoleIP, err := waitForPeer(ctx, clientNode, "waypoint-console-demo")
	if err != nil {
		fatal("%v", err)
	}

	target, _ := url.Parse("http://" + net.JoinHostPort(consoleIP, "8080"))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientNode.Dial(ctx, network, addr)
		},
		// Results stream as NDJSON; buffering them would hide the fact that
		// the first frame arrives before any rows.
		ResponseHeaderTimeout: 60 * time.Second,
	}
	proxy.FlushInterval = -1
	proxy.Director = func(r *http.Request) {
		r.URL.Scheme = target.Scheme
		r.URL.Host = target.Host
		// The console rejects cross-site requests. The browser's origin is
		// this local address, so rewrite both headers to match what the
		// console sees as its own origin.
		if r.Header.Get("Origin") != "" {
			r.Header.Set("Origin", target.String())
		}
		r.Host = target.Host
	}

	local := &http.Server{
		Addr:              *localAddr,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = local.Shutdown(shutdownCtx)
	}()

	banner(*localAddr, *preset, strings.Join(databases, ", "), *pgBackend)

	if err := local.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal("local listener: %v", err)
	}

	stop()
	select {
	case err := <-errCh:
		if err != nil {
			fatal("waypoint: %v", err)
		}
	case <-time.After(15 * time.Second):
	}
	fmt.Fprintln(os.Stderr, "shut down.")
}

// quotedList renders a TOML string array body.
func quotedList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, s := range items {
		quoted = append(quoted, fmt.Sprintf("%q", s))
	}
	return strings.Join(quoted, ", ")
}

func waitForPeer(ctx context.Context, node *tsnet.Server, hostname string) (string, error) {
	lc, err := node.LocalClient()
	if err != nil {
		return "", fmt.Errorf("local client: %w", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		st, err := lc.Status(ctx)
		if err != nil {
			return "", fmt.Errorf("status: %w", err)
		}
		for _, peer := range st.Peer {
			if peer.HostName == hostname && len(peer.TailscaleIPs) > 0 {
				return peer.TailscaleIPs[0].String(), nil
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return "", fmt.Errorf("timed out waiting for peer %q", hostname)
}

func banner(addr, preset, database, backend string) {
	writable := preset == "readwrite" || preset == "admin"
	writeHint := "writes are allowed"
	altPreset := "  Re-run with -preset readonly to see the permission warnings.\n"
	if !writable {
		writeHint = "writes are blocked — the console warns before you run one"
		altPreset = "  Re-run with -preset readwrite to allow writes.\n"
	}
	fmt.Fprintf(os.Stderr, `
────────────────────────────────────────────────────────────────────────
  Console ready:   http://%s

  identity   console-browser (mock tailnet, real WhoIs)
  grant      %s on %s — %s
  backend    %s

  Try:
    SELECT * FROM labels l JOIN            multi-hop join completion
    SELECT * FROM order_items oi JOIN      composite-key ON clause
    UPDATE customers SET name = 'x'        permission warning inline
    SELECT pg_sleep(30)  then press Esc    cancellation
    Cmd/Ctrl+K                             command palette

%s  Ctrl-C to stop.
────────────────────────────────────────────────────────────────────────

`, addr, preset, database, writeHint, backend, altPreset)
}

// testShim adapts this command to the testing.TB surface that
// integration.RunDERPAndSTUN expects.
//
// testing.TB has an unexported method so it cannot be implemented outside the
// testing package; embedding the interface satisfies that while letting the
// handful of methods the DERP helper actually calls be overridden below. The
// embedded value stays nil on purpose — anything else calling into it is a
// method this shim was wrong not to provide, and panicking says so loudly.
type testShim struct {
	testing.TB
	mu       sync.Mutex
	cleanups []func()
}

func (t *testShim) Cleanup(f func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cleanups = append(t.cleanups, f)
}

func (t *testShim) runCleanups() {
	t.mu.Lock()
	fns := t.cleanups
	t.cleanups = nil
	t.mu.Unlock()
	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
}

func (t *testShim) Helper()                      {}
func (t *testShim) Name() string                 { return "waypoint-console-demo" }
func (t *testShim) Log(args ...any)              {}
func (t *testShim) Logf(f string, args ...any)   {}
func (t *testShim) Error(args ...any)            { fmt.Fprintln(os.Stderr, args...) }
func (t *testShim) Errorf(f string, args ...any) { fmt.Fprintf(os.Stderr, f+"\n", args...) }
func (t *testShim) Fatal(args ...any)            { t.Error(args...); os.Exit(1) }
func (t *testShim) Fatalf(f string, args ...any) { t.Errorf(f, args...); os.Exit(1) }
func (t *testShim) Failed() bool                 { return false }

func (t *testShim) TempDir() string {
	d, err := os.MkdirTemp("", "console-demo-derp")
	if err != nil {
		fatal("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
