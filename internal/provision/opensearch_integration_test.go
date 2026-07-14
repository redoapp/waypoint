//go:build integration

package provision

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

// setupOpenSearchProvisioner returns a provisioner wired to a real OpenSearch
// container and the backend host:port.
func setupOpenSearchProvisioner(t *testing.T) (*OpenSearchProvisioner, string) {
	t.Helper()
	backend := testutil.OpenSearchBackend(t)
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "osinttest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := NewOpenSearchProvisioner(
		testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword,
		backend, "wp_os_", "test", false, store, logger, nil,
	)
	return p, backend
}

// osRequest issues an authenticated HTTP request to the OpenSearch backend and
// returns the status code and body.
func osRequest(t *testing.T, backend, method, path, user, pass string, body io.Reader) (int, []byte) {
	t.Helper()
	// path may include a query string (e.g. "/idx/_doc?refresh=true"); build the
	// target as a full URL string so it is preserved rather than escaped.
	req, err := http.NewRequest(method, "http://"+backend+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.SetBasicAuth(user, pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// deleteOpenSearchUser removes a provisioned internal user as admin.
func deleteOpenSearchUser(t *testing.T, backend, username string) {
	osRequest(t, backend, http.MethodDelete,
		"/_plugins/_security/api/internalusers/"+url.PathEscape(username),
		testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword, nil)
}

func TestIntegration_OpenSearchProvisioner_CreatesRoleAndUser(t *testing.T) {
	p, backend := setupOpenSearchProvisioner(t)

	spec := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro", "cluster_monitor"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"logs-*"}, AllowedActions: []string{"read", "search"}},
		},
	}

	user, pass, err := p.EnsureUser(context.Background(), "alice@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, user) })

	if user == "" || pass == "" {
		t.Fatal("expected non-empty username and password")
	}

	// The deterministic role should exist in the Security plugin.
	roleName := OpenSearchRoleName(spec)
	status, body := osRequest(t, backend, http.MethodGet,
		"/_plugins/_security/api/roles/"+url.PathEscape(roleName),
		testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword, nil)
	if status != http.StatusOK {
		t.Fatalf("role lookup status = %d: %s", status, body)
	}

	// The internal user should exist and be mapped to the role.
	status, body = osRequest(t, backend, http.MethodGet,
		"/_plugins/_security/api/internalusers/"+url.PathEscape(user),
		testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword, nil)
	if status != http.StatusOK {
		t.Fatalf("internal user lookup status = %d: %s", status, body)
	}
	if !strings.Contains(string(body), roleName) {
		t.Fatalf("internal user not mapped to role %q: %s", roleName, body)
	}

	// The provisioned credentials should authenticate against the cluster.
	status, body = osRequest(t, backend, http.MethodGet, "/_cluster/health", user, pass, nil)
	if status != http.StatusOK {
		t.Fatalf("provisioned user cluster health status = %d: %s", status, body)
	}
}

func TestIntegration_OpenSearchProvisioner_PasswordCaching(t *testing.T) {
	p, backend := setupOpenSearchProvisioner(t)
	spec := OpenSearchRoleSpec{ClusterPermissions: []string{"cluster_composite_ops_ro", "cluster_monitor"}}

	user, pass1, err := p.EnsureUser(context.Background(), "cache@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser first: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, user) })

	_, pass2, err := p.EnsureUser(context.Background(), "cache@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser second: %v", err)
	}
	if pass1 != pass2 {
		t.Fatal("password should be cached and reused within the TTL window")
	}

	status, body := osRequest(t, backend, http.MethodGet, "/_cluster/health", user, pass1, nil)
	if status != http.StatusOK {
		t.Fatalf("cached credential auth status = %d: %s", status, body)
	}
}

func TestIntegration_OpenSearchProvisioner_RotatesAfterCacheExpiry(t *testing.T) {
	p, backend := setupOpenSearchProvisioner(t)
	spec := OpenSearchRoleSpec{ClusterPermissions: []string{"cluster_composite_ops_ro", "cluster_monitor"}}

	user, pass1, err := p.EnsureUser(context.Background(), "rotate@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser first: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, user) })

	p.credCache.Delete(user)

	_, pass2, err := p.EnsureUser(context.Background(), "rotate@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser second: %v", err)
	}
	if pass1 == pass2 {
		t.Fatal("password should rotate after cache expiry")
	}

	// The rotated password must work and the old one must not.
	if status, body := osRequest(t, backend, http.MethodGet, "/_cluster/health", user, pass2, nil); status != http.StatusOK {
		t.Fatalf("rotated credential auth status = %d: %s", status, body)
	}
	// Give the security cache a moment to invalidate the old password.
	time.Sleep(500 * time.Millisecond)
	if status, _ := osRequest(t, backend, http.MethodGet, "/_cluster/health", user, pass1, nil); status == http.StatusOK {
		t.Fatal("old password should no longer authenticate after rotation")
	}
}

func TestIntegration_OpenSearchProvisioner_ReadonlyCannotWrite(t *testing.T) {
	p, backend := setupOpenSearchProvisioner(t)

	// Read-only grant on a dedicated index pattern.
	spec := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"ro-*"}, AllowedActions: []string{"read", "search", "indices:data/read/*"}},
		},
	}
	user, pass, err := p.EnsureUser(context.Background(), "readonly@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, user) })

	// Seed a document as admin so the index exists.
	doc := strings.NewReader(`{"seed":true}`)
	if status, body := osRequest(t, backend, http.MethodPost, "/ro-2026/_doc?refresh=true",
		testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword, doc); status/100 != 2 {
		t.Fatalf("seed doc status = %d: %s", status, body)
	}

	// Read as the readonly user should succeed.
	if status, body := osRequest(t, backend, http.MethodGet, "/ro-2026/_search", user, pass, nil); status != http.StatusOK {
		t.Fatalf("readonly search status = %d: %s", status, body)
	}

	// Write as the readonly user should be forbidden.
	writeDoc := strings.NewReader(`{"blocked":true}`)
	status, body := osRequest(t, backend, http.MethodPost, "/ro-2026/_doc", user, pass, writeDoc)
	if status != http.StatusForbidden {
		t.Fatalf("readonly write status = %d (want 403): %s", status, body)
	}
}

func TestIntegration_OpenSearchProvisioner_RoleReuseForEquivalentGrants(t *testing.T) {
	p, backend := setupOpenSearchProvisioner(t)

	// Two specs that normalize to the same grant set must map to one role.
	specA := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro", "cluster_composite_ops_ro"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"logs-*"}, AllowedActions: []string{"read", "search"}},
		},
	}
	specB := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"logs-*"}, AllowedActions: []string{"search", "read"}},
		},
	}
	if OpenSearchRoleName(specA) != OpenSearchRoleName(specB) {
		t.Fatalf("equivalent specs produced different role names: %s vs %s", OpenSearchRoleName(specA), OpenSearchRoleName(specB))
	}

	userA, _, err := p.EnsureUser(context.Background(), "reuse-a@example.com", "test-node", specA)
	if err != nil {
		t.Fatalf("EnsureUser A: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, userA) })

	userB, _, err := p.EnsureUser(context.Background(), "reuse-b@example.com", "test-node", specB)
	if err != nil {
		t.Fatalf("EnsureUser B: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, userB) })

	roleName := OpenSearchRoleName(specA)
	status, body := osRequest(t, backend, http.MethodGet,
		"/_plugins/_security/api/roles/"+url.PathEscape(roleName),
		testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword, nil)
	if status != http.StatusOK {
		t.Fatalf("shared role lookup status = %d: %s", status, body)
	}

	// Sanity-check the role document is well-formed JSON keyed by the role name.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("role body not JSON: %v (%s)", err, body)
	}
	if _, ok := doc[roleName]; !ok {
		t.Fatalf("role document missing key %q: %s", roleName, body)
	}

	if userA == userB {
		t.Fatalf("distinct logins should map to distinct usernames, both = %q", userA)
	}
}
