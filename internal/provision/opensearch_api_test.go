package provision

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// osAPIRequest records a single call the provisioner made to the mock Security
// REST API.
type osAPIRequest struct {
	method   string
	path     string
	authUser string
	authPass string
	body     map[string]any
}

// mockOpenSearchAPI stands in for the OpenSearch Security plugin REST API so the
// provisioner's real HTTP code path (doJSON, ensureRole, ensureInternalUser) is
// exercised without a container.
type mockOpenSearchAPI struct {
	mu       sync.Mutex
	requests []osAPIRequest
	// failPath, when set, makes any request whose path contains it return
	// failStatus with a JSON error body.
	failPath   string
	failStatus int
}

func (m *mockOpenSearchAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		var body map[string]any
		if data, _ := io.ReadAll(r.Body); len(data) > 0 {
			_ = json.Unmarshal(data, &body)
		}

		m.mu.Lock()
		m.requests = append(m.requests, osAPIRequest{
			method:   r.Method,
			path:     r.URL.Path,
			authUser: user,
			authPass: pass,
			body:     body,
		})
		failPath, failStatus := m.failPath, m.failStatus
		m.mu.Unlock()

		if failPath != "" && strings.Contains(r.URL.Path, failPath) {
			w.WriteHeader(failStatus)
			_, _ = io.WriteString(w, `{"status":"error","reason":"boom"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"OK"}`)
	})
}

func (m *mockOpenSearchAPI) snapshot() []osAPIRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]osAPIRequest(nil), m.requests...)
}

// newOpenSearchTestProvisioner wires a provisioner (no Redis, no lock) to the
// given backend address.
func newOpenSearchTestProvisioner(backend string, tls bool) *OpenSearchProvisioner {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewOpenSearchProvisioner("admin", "adminpass", backend, "wp_os_", "search", tls, nil, logger, nil)
}

func backendHostPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	return u.Host
}

func requireOne(t *testing.T, reqs []osAPIRequest, method, pathContains string) osAPIRequest {
	t.Helper()
	var found []osAPIRequest
	for _, r := range reqs {
		if r.method == method && strings.Contains(r.path, pathContains) {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one %s request containing %q, got %d (%+v)", method, pathContains, len(found), reqs)
	}
	return found[0]
}

func TestOpenSearchProvisioner_EnsureUser_CreatesRoleAndUser(t *testing.T) {
	api := &mockOpenSearchAPI{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	p := newOpenSearchTestProvisioner(backendHostPort(t, srv), false)

	spec := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"logs-*"}, AllowedActions: []string{"read"}},
		},
	}

	user, pass, err := p.EnsureUser(context.Background(), "alice@example.com", "node-1", spec)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if user == "" || pass == "" {
		t.Fatalf("expected non-empty user/pass, got %q/%q", user, pass)
	}
	if !strings.HasPrefix(user, "wp_os_") {
		t.Fatalf("expected wp_os_ prefix, got %q", user)
	}

	reqs := api.snapshot()

	roleReq := requireOne(t, reqs, http.MethodPut, "/_plugins/_security/api/roles/")
	if roleReq.authUser != "admin" || roleReq.authPass != "adminpass" {
		t.Fatalf("role request admin auth = %q/%q", roleReq.authUser, roleReq.authPass)
	}
	if !strings.Contains(roleReq.path, OpenSearchRoleName(spec)) {
		t.Fatalf("role path %q does not contain deterministic role name %q", roleReq.path, OpenSearchRoleName(spec))
	}
	if _, ok := roleReq.body["cluster_permissions"]; !ok {
		t.Fatalf("role body missing cluster_permissions: %+v", roleReq.body)
	}

	userReq := requireOne(t, reqs, http.MethodPut, "/_plugins/_security/api/internalusers/")
	if !strings.HasSuffix(userReq.path, user) {
		t.Fatalf("internal user path %q does not end with %q", userReq.path, user)
	}
	if got, _ := userReq.body["password"].(string); got != pass {
		t.Fatalf("internal user body password = %q, want %q", got, pass)
	}
	roles, ok := userReq.body["opendistro_security_roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != OpenSearchRoleName(spec) {
		t.Fatalf("internal user roles = %+v, want [%s]", userReq.body["opendistro_security_roles"], OpenSearchRoleName(spec))
	}
}

func TestOpenSearchProvisioner_EnsureUser_CachesPassword(t *testing.T) {
	api := &mockOpenSearchAPI{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	p := newOpenSearchTestProvisioner(backendHostPort(t, srv), false)
	spec := OpenSearchRoleSpec{ClusterPermissions: []string{"cluster_composite_ops_ro"}}

	user1, pass1, err := p.EnsureUser(context.Background(), "bob@example.com", "node-1", spec)
	if err != nil {
		t.Fatalf("EnsureUser first: %v", err)
	}
	user2, pass2, err := p.EnsureUser(context.Background(), "bob@example.com", "node-1", spec)
	if err != nil {
		t.Fatalf("EnsureUser second: %v", err)
	}

	if user1 != user2 {
		t.Fatalf("username changed between calls: %q vs %q", user1, user2)
	}
	if pass1 != pass2 {
		t.Fatalf("password not cached: %q vs %q", pass1, pass2)
	}

	// Both calls should still reconcile role + user (idempotent PUTs), so we
	// expect two role PUTs and two internal-user PUTs.
	reqs := api.snapshot()
	var rolePuts, userPuts int
	for _, r := range reqs {
		if r.method != http.MethodPut {
			continue
		}
		if strings.Contains(r.path, "/api/roles/") {
			rolePuts++
		}
		if strings.Contains(r.path, "/api/internalusers/") {
			userPuts++
		}
	}
	if rolePuts != 2 || userPuts != 2 {
		t.Fatalf("expected 2 role PUTs and 2 user PUTs, got %d/%d", rolePuts, userPuts)
	}
}

func TestOpenSearchProvisioner_EnsureUser_RotatesAfterCacheExpiry(t *testing.T) {
	api := &mockOpenSearchAPI{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	p := newOpenSearchTestProvisioner(backendHostPort(t, srv), false)
	spec := OpenSearchRoleSpec{ClusterPermissions: []string{"cluster_composite_ops_ro"}}

	user, pass1, err := p.EnsureUser(context.Background(), "carol@example.com", "node-1", spec)
	if err != nil {
		t.Fatalf("EnsureUser first: %v", err)
	}

	// Simulate cache expiry by dropping the cached credential.
	p.credCache.Delete(user)

	_, pass2, err := p.EnsureUser(context.Background(), "carol@example.com", "node-1", spec)
	if err != nil {
		t.Fatalf("EnsureUser second: %v", err)
	}
	if pass1 == pass2 {
		t.Fatalf("password should rotate after cache expiry, got %q both times", pass1)
	}
}

func TestOpenSearchProvisioner_EnsureUser_EmptySpecRejected(t *testing.T) {
	api := &mockOpenSearchAPI{}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	p := newOpenSearchTestProvisioner(backendHostPort(t, srv), false)

	_, _, err := p.EnsureUser(context.Background(), "dave@example.com", "node-1", OpenSearchRoleSpec{})
	if err == nil {
		t.Fatal("expected error for empty permission spec")
	}
	if len(api.snapshot()) != 0 {
		t.Fatalf("empty spec should make no API calls, got %+v", api.snapshot())
	}
}

func TestOpenSearchProvisioner_EnsureUser_PropagatesRoleAPIError(t *testing.T) {
	api := &mockOpenSearchAPI{failPath: "/api/roles/", failStatus: http.StatusForbidden}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	p := newOpenSearchTestProvisioner(backendHostPort(t, srv), false)
	spec := OpenSearchRoleSpec{ClusterPermissions: []string{"cluster_composite_ops_ro"}}

	_, _, err := p.EnsureUser(context.Background(), "erin@example.com", "node-1", spec)
	if err == nil {
		t.Fatal("expected error when role API returns non-2xx")
	}
	if !strings.Contains(err.Error(), "ensure role") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error should mention role failure and status 403, got: %v", err)
	}

	// The role PUT failed, so the internal-user PUT must not have happened.
	for _, r := range api.snapshot() {
		if strings.Contains(r.path, "/api/internalusers/") {
			t.Fatalf("internal user should not be created after role failure: %+v", r)
		}
	}
}

func TestOpenSearchProvisioner_EnsureUser_PropagatesUserAPIError(t *testing.T) {
	api := &mockOpenSearchAPI{failPath: "/api/internalusers/", failStatus: http.StatusBadRequest}
	srv := httptest.NewServer(api.handler())
	defer srv.Close()

	p := newOpenSearchTestProvisioner(backendHostPort(t, srv), false)
	spec := OpenSearchRoleSpec{ClusterPermissions: []string{"cluster_composite_ops_ro"}}

	_, _, err := p.EnsureUser(context.Background(), "frank@example.com", "node-1", spec)
	if err == nil {
		t.Fatal("expected error when internal user API returns non-2xx")
	}
	if !strings.Contains(err.Error(), "ensure internal user") {
		t.Fatalf("error should mention internal user failure, got: %v", err)
	}
}

func TestOpenSearchProvisioner_EnsureUser_BackendTLS(t *testing.T) {
	api := &mockOpenSearchAPI{}
	srv := httptest.NewTLSServer(api.handler())
	defer srv.Close()

	// backendTLS=true makes the provisioner speak HTTPS with InsecureSkipVerify,
	// which is required to accept httptest's self-signed certificate.
	p := newOpenSearchTestProvisioner(backendHostPort(t, srv), true)
	spec := OpenSearchRoleSpec{ClusterPermissions: []string{"cluster_composite_ops_ro"}}

	user, pass, err := p.EnsureUser(context.Background(), "grace@example.com", "node-1", spec)
	if err != nil {
		t.Fatalf("EnsureUser over TLS: %v", err)
	}
	if user == "" || pass == "" {
		t.Fatal("expected non-empty credentials over TLS")
	}
	if len(api.snapshot()) < 2 {
		t.Fatalf("expected role + user PUTs over TLS, got %+v", api.snapshot())
	}
}
