package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/restrict"
)

func TestOpenSearchCollectAccess_MergesRulesAndErrors(t *testing.T) {
	p := &OpenSearchProxy{Name: "search"}

	// Two matched rules for the same backend should merge into one spec.
	result := &auth.AuthResult{
		LoginName: "u@example.com",
		MatchedRules: []auth.CapRule{
			{Backends: map[string]auth.BackendCap{"search": {OpenSearch: &auth.OpenSearchCap{
				Indices: map[string]auth.OpenSearchIndexPermissions{"logs-*": {Permissions: []string{"readonly"}}},
			}}}},
			{Backends: map[string]auth.BackendCap{"search": {OpenSearch: &auth.OpenSearchCap{
				Indices: map[string]auth.OpenSearchIndexPermissions{"metrics-*": {Permissions: []string{"readonly"}}},
			}}}},
		},
	}
	spec, err := p.collectAccess(result)
	if err != nil {
		t.Fatalf("collectAccess: %v", err)
	}
	var patterns []string
	for _, ip := range spec.IndexPermissions {
		patterns = append(patterns, ip.IndexPatterns...)
	}
	if !contains(patterns, "logs-*") || !contains(patterns, "metrics-*") {
		t.Fatalf("expected merged index patterns, got %v", patterns)
	}

	// No rule for this backend should be an error.
	_, err = p.collectAccess(&auth.AuthResult{
		LoginName: "u@example.com",
		MatchedRules: []auth.CapRule{
			{Backends: map[string]auth.BackendCap{"other": {OpenSearch: &auth.OpenSearchCap{}}}},
		},
	})
	if err == nil {
		t.Fatal("expected error when no matched rule targets this backend")
	}
}

func TestOpenSearchShouldRewriteNodeInfo(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/_nodes", true},
		{"/_nodes/", true},
		{"/_nodes/http", true},
		{"/_nodes/_all/http", true},
		{"/_nodes/stats", false},
		{"/_nodes/hot_threads", false},
		{"/_nodes/usage", false},
		{"/_nodes/reload_secure_settings", false},
		{"/_search", false},
		{"/logs-2026/_search", false},
	}
	for _, tc := range cases {
		req, err := http.NewRequest(http.MethodGet, "http://waypoint.local"+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := shouldRewriteOpenSearchNodeInfo(req); got != tc.want {
			t.Errorf("shouldRewriteOpenSearchNodeInfo(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
	if shouldRewriteOpenSearchNodeInfo(nil) {
		t.Error("nil request should not be rewritten")
	}
}

func TestOpenSearchRewriteNodeInfoJSON_EdgeCases(t *testing.T) {
	// No "nodes" key: unchanged.
	if _, changed, err := rewriteOpenSearchNodeInfoJSON([]byte(`{"cluster_name":"x"}`), "adv:9200"); err != nil || changed {
		t.Fatalf("no nodes key: changed=%v err=%v", changed, err)
	}

	// Node without http block: unchanged.
	if _, changed, err := rewriteOpenSearchNodeInfoJSON([]byte(`{"nodes":{"n1":{"name":"n1"}}}`), "adv:9200"); err != nil || changed {
		t.Fatalf("node without http: changed=%v err=%v", changed, err)
	}

	// publish_address already equal to advertise addr: no change.
	already := `{"nodes":{"n1":{"http":{"publish_address":"adv:9200"}}}}`
	if _, changed, err := rewriteOpenSearchNodeInfoJSON([]byte(already), "adv:9200"); err != nil || changed {
		t.Fatalf("already-correct: changed=%v err=%v", changed, err)
	}

	// Empty advertise addr: never rewrite.
	if _, changed, err := rewriteOpenSearchNodeInfoJSON([]byte(`{"nodes":{"n1":{"http":{"publish_address":"x:1"}}}}`), ""); err != nil || changed {
		t.Fatalf("empty advertise: changed=%v err=%v", changed, err)
	}

	// Malformed JSON: error, unchanged.
	if _, changed, err := rewriteOpenSearchNodeInfoJSON([]byte(`{not json`), "adv:9200"); err == nil || changed {
		t.Fatalf("malformed JSON: changed=%v err=%v", changed, err)
	}

	// Multiple nodes, mixed: rewrites only the ones with an http block.
	multi := `{"nodes":{"n1":{"http":{"publish_address":"10.0.0.1:9200"}},"n2":{"transport":{"publish_address":"10.0.0.2:9300"}}}}`
	out, changed, err := rewriteOpenSearchNodeInfoJSON([]byte(multi), "adv:9200")
	if err != nil || !changed {
		t.Fatalf("multi rewrite: changed=%v err=%v", changed, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	n1 := doc["nodes"].(map[string]any)["n1"].(map[string]any)["http"].(map[string]any)
	if n1["publish_address"] != "adv:9200" {
		t.Fatalf("n1 publish_address = %v", n1["publish_address"])
	}
}

func TestOpenSearchRemoveHopByHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Custom-Hop, Keep-Alive")
	h.Set("X-Custom-Hop", "drop-me")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "websocket")
	h.Set("X-Keep", "retain")

	removeHopByHopHeaders(h)

	for _, name := range []string{"Connection", "X-Custom-Hop", "Keep-Alive", "Transfer-Encoding", "Upgrade"} {
		if h.Get(name) != "" {
			t.Errorf("header %q should have been removed, got %q", name, h.Get(name))
		}
	}
	if h.Get("X-Keep") != "retain" {
		t.Errorf("non-hop-by-hop header X-Keep was dropped")
	}
}

func TestOpenSearchEffectiveAdvertiseAddr(t *testing.T) {
	// Configured advertise address wins.
	p := &OpenSearchProxy{AdvertiseAddr: "waypoint-search:9200"}
	if got := p.effectiveAdvertiseAddr(nil, ""); got != "waypoint-search:9200" {
		t.Fatalf("configured advertise addr = %q", got)
	}

	// Falls back to the client's local address when unset.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	empty := &OpenSearchProxy{}
	if got := empty.effectiveAdvertiseAddr(server, ""); got != server.LocalAddr().String() {
		t.Fatalf("fallback advertise addr = %q, want %q", got, server.LocalAddr().String())
	}
}

func TestOpenSearchRemoteHost(t *testing.T) {
	if got := remoteHost("100.64.0.1:54321"); got != "100.64.0.1" {
		t.Fatalf("remoteHost with port = %q", got)
	}
	if got := remoteHost("bare-host"); got != "bare-host" {
		t.Fatalf("remoteHost without port = %q", got)
	}
}

// TestOpenSearchHandleConn_DatabaseModeProvisionsAndProxies drives a full
// database-mode connection: the proxy provisions a backend user via the Security
// API (served by the same httptest backend) and then proxies a query using the
// freshly provisioned credentials.
func TestOpenSearchHandleConn_DatabaseModeProvisionsAndProxies(t *testing.T) {
	var mu sync.Mutex
	var provisionedUser, provisionedPass string
	var roleEnsured, userEnsured bool
	var queryCount int
	queryErrs := make(chan error, 4)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/_plugins/_security/api/roles/"):
			mu.Lock()
			roleEnsured = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/_plugins/_security/api/internalusers/"):
			data, _ := io.ReadAll(r.Body)
			var payload map[string]any
			_ = json.Unmarshal(data, &payload)
			name := strings.TrimPrefix(r.URL.Path, "/_plugins/_security/api/internalusers/")
			name, _ = url.PathUnescape(name)
			mu.Lock()
			userEnsured = true
			provisionedUser = name
			provisionedPass, _ = payload["password"].(string)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			user, pass, ok := r.BasicAuth()
			mu.Lock()
			wantUser, wantPass := provisionedUser, provisionedPass
			queryCount++
			mu.Unlock()
			if !ok || user != wantUser || pass != wantPass {
				queryErrs <- fmt.Errorf("query auth = %q/%q ok=%v, want %q/%q", user, pass, ok, wantUser, wantPass)
			}
			if strings.Contains(r.Header.Get("Authorization"), "client") {
				queryErrs <- fmt.Errorf("client Authorization leaked to backend")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	m := metrics.Noop()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := restrict.NewRedisStore(rdb, "osdbtest:", m)
	prov := provision.NewOpenSearchProvisioner("admin", "adminpass", backendAddr, "wp_os_", "search", false, nil, logger, nil)

	authz := &countingOpenSearchAuthorizer{result: openSearchAuthResult()}
	p := &OpenSearchProxy{
		Backend:     backendAddr,
		Name:        "search",
		Auth:        authz,
		Tracker:     restrict.NewTracker(store, m, logger),
		Provisioner: prov,
		Metrics:     m,
		OpenSearchConfig: &config.OpenSearchAdmin{
			Provision: &config.OpenSearchProvision{Mode: config.OpenSearchProvisionDatabase},
		},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	proxySide, clientSide := net.Pipe()
	defer clientSide.Close()
	setPipeDeadline(t, proxySide, clientSide)

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.HandleConn(context.Background(), proxySide)
	}()

	reader := bufio.NewReader(clientSide)
	for _, path := range []string{"/_cluster/health", "/logs-2026/_search"} {
		req, err := http.NewRequest(http.MethodGet, "http://waypoint.local"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("client:secret")))
		if err := req.Write(clientSide); err != nil {
			t.Fatalf("write request %s: %v", path, err)
		}
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatalf("read response %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status for %s = %d", path, resp.StatusCode)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	clientSide.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit after client close")
	}

	mu.Lock()
	defer mu.Unlock()
	if !roleEnsured || !userEnsured {
		t.Fatalf("expected role and user to be provisioned: role=%v user=%v", roleEnsured, userEnsured)
	}
	if !strings.HasPrefix(provisionedUser, "wp_os_") {
		t.Fatalf("provisioned user %q missing wp_os_ prefix", provisionedUser)
	}
	if queryCount != 2 {
		t.Fatalf("backend query count = %d, want 2", queryCount)
	}
	select {
	case err := <-queryErrs:
		t.Fatal(err)
	default:
	}
}

// TestOpenSearchHandleConn_RewritesNodeInfoOverWire confirms the /_nodes publish
// address is rewritten to the advertised endpoint on the response the client
// receives.
func TestOpenSearchHandleConn_RewritesNodeInfoOverWire(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"nodes":{"n1":{"http":{"publish_address":"10.1.2.3:9200"}}}}`)
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	m := metrics.Noop()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := &OpenSearchProxy{
		Backend:       backendAddr,
		Name:          "search",
		AdvertiseAddr: "waypoint-search:9200",
		Auth:          &countingOpenSearchAuthorizer{result: openSearchAuthResult()},
		Tracker:       restrict.NewTracker(restrict.NewRedisStore(rdb, "osnodetest:", m), m, logger),
		Metrics:       m,
		OpenSearchConfig: &config.OpenSearchAdmin{
			Provision: &config.OpenSearchProvision{
				Mode: config.OpenSearchProvisionStatic,
				StaticUsers: []config.OpenSearchStaticUser{
					{
						Username:           "logs_ro",
						Password:           "secret",
						ClusterPermissions: []string{"cluster_composite_ops_ro"},
						IndexPermissions: []config.OpenSearchStaticIndexPermission{
							{IndexPatterns: []string{"logs-*"}, AllowedActions: []string{"read"}},
						},
					},
				},
			},
		},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	proxySide, clientSide := net.Pipe()
	defer clientSide.Close()
	setPipeDeadline(t, proxySide, clientSide)

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.HandleConn(context.Background(), proxySide)
	}()

	reader := bufio.NewReader(clientSide)
	req, err := http.NewRequest(http.MethodGet, "http://waypoint.local/_nodes/http", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("client:secret")))
	if err := req.Write(clientSide); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	clientSide.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit after client close")
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal client body: %v (%s)", err, body)
	}
	got := doc["nodes"].(map[string]any)["n1"].(map[string]any)["http"].(map[string]any)["publish_address"]
	if got != "waypoint-search:9200" {
		t.Fatalf("publish_address = %v, want waypoint-search:9200", got)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
