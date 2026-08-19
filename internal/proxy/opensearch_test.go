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
	"strings"
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

type countingOpenSearchAuthorizer struct {
	result *auth.AuthResult
	err    error
	calls  atomic.Int64
}

func (a *countingOpenSearchAuthorizer) Authorize(context.Context, string, string) (*auth.AuthResult, error) {
	a.calls.Add(1)
	return a.result, a.err
}

func TestOpenSearchStaticCredentialMatchesNormalizedGrantSet(t *testing.T) {
	p := &OpenSearchProxy{
		OpenSearchConfig: &config.OpenSearchAdmin{
			Provision: &config.OpenSearchProvision{
				Mode: config.OpenSearchProvisionStatic,
				StaticUsers: []config.OpenSearchStaticUser{
					{
						Name:               "logs-readonly",
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
	}

	cred, err := p.selectStaticCredential(provision.OpenSearchRoleSpec{
		IndexPermissions: []provision.OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"logs-*"}, AllowedActions: []string{"read"}},
		},
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
	})
	if err != nil {
		t.Fatalf("selectStaticCredential: %v", err)
	}
	if cred.Username != "logs_ro" || cred.Password != "secret" {
		t.Fatalf("credential = %+v", cred)
	}
}

func TestOpenSearchPrepareBackendRequestStripsClientAuthAndInjectsBackendAuth(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://waypoint.local/_search", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic client")
	req.Header.Set("Proxy-Authorization", "Basic proxy")
	req.Header.Set("Connection", "X-Drop")
	req.Header.Set("X-Drop", "remove-me")
	req.Header.Set("Accept-Encoding", "gzip")

	if err := prepareOpenSearchBackendRequest(req, "search.internal:9200", true, "backend_user", "backend_pass"); err != nil {
		t.Fatalf("prepareOpenSearchBackendRequest: %v", err)
	}
	if req.URL.Scheme != "https" || req.URL.Host != "search.internal:9200" || req.Host != "search.internal:9200" {
		t.Fatalf("backend URL/host not set correctly: url=%s host=%s", req.URL.String(), req.Host)
	}
	if req.Header.Get("Proxy-Authorization") != "" || req.Header.Get("Accept-Encoding") != "" || req.Header.Get("X-Drop") != "" {
		t.Fatalf("client hop-by-hop/auth headers were not stripped: %v", req.Header)
	}
	user, pass, ok := req.BasicAuth()
	if !ok || user != "backend_user" || pass != "backend_pass" {
		t.Fatalf("backend basic auth = %q/%q ok=%v", user, pass, ok)
	}
}

func TestOpenSearchRewriteNodeInfoJSON(t *testing.T) {
	input := []byte(`{"nodes":{"node-1":{"http":{"publish_address":"10.0.0.1:9200","bound_address":["0.0.0.0:9200"]}}}}`)
	rewritten, changed, err := rewriteOpenSearchNodeInfoJSON(input, "waypoint-search:9200")
	if err != nil {
		t.Fatalf("rewriteOpenSearchNodeInfoJSON: %v", err)
	}
	if !changed {
		t.Fatal("expected rewrite")
	}

	var doc map[string]any
	if err := json.Unmarshal(rewritten, &doc); err != nil {
		t.Fatalf("unmarshal rewritten: %v", err)
	}
	nodes := doc["nodes"].(map[string]any)
	node := nodes["node-1"].(map[string]any)
	httpInfo := node["http"].(map[string]any)
	if httpInfo["publish_address"] != "waypoint-search:9200" {
		t.Fatalf("publish_address = %v", httpInfo["publish_address"])
	}
}

func TestOpenSearchHandleConn_StaticKeepAliveUsesOneAuthAndInjectsBackendAuth(t *testing.T) {
	var backendRequests atomic.Int64
	backendErrs := make(chan error, 2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequests.Add(1)
		user, pass, ok := r.BasicAuth()
		if !ok || user != "logs_ro" || pass != "secret" {
			backendErrs <- fmt.Errorf("backend auth = %q/%q ok=%v", user, pass, ok)
		}
		if strings.Contains(r.Header.Get("Authorization"), "client") {
			backendErrs <- fmt.Errorf("client Authorization leaked to backend")
		}
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"path":%q}`, r.URL.Path)
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	authz := &countingOpenSearchAuthorizer{result: openSearchAuthResult()}
	m := metrics.Noop()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := &OpenSearchProxy{
		Backend: backendAddr,
		Name:    "search",
		Auth:    authz,
		Tracker: restrict.NewTracker(
			restrict.NewRedisStore(rdb, "opensearchproxytest:", m),
			m,
			logger,
		),
		Metrics: m,
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

	if authz.calls.Load() != 1 {
		t.Fatalf("authorize calls = %d, want 1", authz.calls.Load())
	}
	if backendRequests.Load() != 2 {
		t.Fatalf("backend requests = %d, want 2", backendRequests.Load())
	}
	select {
	case err := <-backendErrs:
		t.Fatal(err)
	default:
	}
}

func openSearchAuthResult() *auth.AuthResult {
	return &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		MatchedRules: []auth.CapRule{
			{
				Backends: map[string]auth.BackendCap{
					"search": {
						OpenSearch: &auth.OpenSearchCap{
							Indices: map[string]auth.OpenSearchIndexPermissions{
								"logs-*": {Permissions: []string{"readonly"}},
							},
						},
					},
				},
			},
		},
	}
}
