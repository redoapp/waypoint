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

// osSearchResponse is a minimal projection of an OpenSearch _search response.
type osSearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source map[string]any `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// osSeed indexes a document into the backend as admin (refreshing so it is
// immediately searchable).
func osSeed(t *testing.T, backend, index, jsonDoc string) {
	t.Helper()
	status, body := osRequest(t, backend, http.MethodPost, "/"+index+"/_doc?refresh=true",
		testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword, strings.NewReader(jsonDoc))
	if status/100 != 2 {
		t.Fatalf("seed %s status = %d: %s", index, status, body)
	}
}

// osSearchAs runs a match_all search against index as the given user and returns
// the parsed response.
func osSearchAs(t *testing.T, backend, index, user, pass string) osSearchResponse {
	t.Helper()
	status, body := osRequest(t, backend, http.MethodGet, "/"+index+"/_search", user, pass, nil)
	if status != http.StatusOK {
		t.Fatalf("search %s status = %d: %s", index, status, body)
	}
	var resp osSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode search response: %v (%s)", err, body)
	}
	return resp
}

// TestIntegration_OpenSearchProvisioner_DLSRestrictsDocuments verifies that a
// document-level security query on the provisioned role hides non-matching
// documents from the provisioned user while the admin still sees everything.
func TestIntegration_OpenSearchProvisioner_DLSRestrictsDocuments(t *testing.T) {
	p, backend := setupOpenSearchProvisioner(t)

	osSeed(t, backend, "dls-2026", `{"level":"public","msg":"visible"}`)
	osSeed(t, backend, "dls-2026", `{"level":"secret","msg":"hidden"}`)

	spec := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{
				IndexPatterns:  []string{"dls-*"},
				AllowedActions: []string{"read"},
				DLS:            `{"term":{"level.keyword":"public"}}`,
			},
		},
	}
	user, pass, err := p.EnsureUser(context.Background(), "dls@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, user) })

	// Admin sees both documents.
	if got := osSearchAs(t, backend, "dls-2026", testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword); got.Hits.Total.Value != 2 {
		t.Fatalf("admin should see 2 docs, got %d", got.Hits.Total.Value)
	}

	// The DLS-scoped user only sees the public document.
	resp := osSearchAs(t, backend, "dls-2026", user, pass)
	if resp.Hits.Total.Value != 1 {
		t.Fatalf("DLS user should see 1 doc, got %d", resp.Hits.Total.Value)
	}
	if len(resp.Hits.Hits) != 1 || resp.Hits.Hits[0].Source["level"] != "public" {
		t.Fatalf("DLS user saw unexpected doc: %+v", resp.Hits.Hits)
	}
}

// TestIntegration_OpenSearchProvisioner_FLSHidesFields verifies that
// field-level security on the provisioned role removes an excluded field from
// the documents the provisioned user can read.
func TestIntegration_OpenSearchProvisioner_FLSHidesFields(t *testing.T) {
	p, backend := setupOpenSearchProvisioner(t)

	osSeed(t, backend, "fls-2026", `{"message":"hello","secret":"topsecret"}`)

	spec := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{
				IndexPatterns:  []string{"fls-*"},
				AllowedActions: []string{"read"},
				FLS:            []string{"~secret"}, // exclude the secret field
			},
		},
	}
	user, pass, err := p.EnsureUser(context.Background(), "fls@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, user) })

	// Admin sees both fields.
	admin := osSearchAs(t, backend, "fls-2026", testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword)
	if len(admin.Hits.Hits) != 1 || admin.Hits.Hits[0].Source["secret"] != "topsecret" {
		t.Fatalf("admin should see the secret field: %+v", admin.Hits.Hits)
	}

	// The FLS-scoped user sees message but not secret.
	resp := osSearchAs(t, backend, "fls-2026", user, pass)
	if len(resp.Hits.Hits) != 1 {
		t.Fatalf("FLS user should see 1 doc, got %d", resp.Hits.Total.Value)
	}
	src := resp.Hits.Hits[0].Source
	if src["message"] != "hello" {
		t.Fatalf("FLS user should still see message, got %+v", src)
	}
	if _, present := src["secret"]; present {
		t.Fatalf("FLS user should not see excluded secret field, got %+v", src)
	}
}

// osTermsAggKey runs a terms aggregation over field for index as the given user
// and returns the first bucket key. OpenSearch field masking anonymizes
// doc-values (used by aggregations), so this is the canonical way to observe a
// masked value.
func osTermsAggKey(t *testing.T, backend, index, field, user, pass string) string {
	t.Helper()
	body := `{"size":0,"aggs":{"v":{"terms":{"field":"` + field + `"}}}}`
	status, raw := osRequest(t, backend, http.MethodPost, "/"+index+"/_search",
		user, pass, strings.NewReader(body))
	if status != http.StatusOK {
		t.Fatalf("agg search %s status = %d: %s", index, status, raw)
	}
	var resp struct {
		Aggregations struct {
			V struct {
				Buckets []struct {
					Key string `json:"key"`
				} `json:"buckets"`
			} `json:"v"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode agg response: %v (%s)", err, raw)
	}
	if len(resp.Aggregations.V.Buckets) == 0 {
		t.Fatalf("no aggregation buckets for %s.%s: %s", index, field, raw)
	}
	return resp.Aggregations.V.Buckets[0].Key
}

// TestIntegration_OpenSearchProvisioner_MaskedFields verifies that field masking
// on the provisioned role replaces a sensitive field value with a masked
// (hashed) value for the provisioned user, while the admin sees the raw value.
// Masking applies to doc-values, so this is observed via a terms aggregation.
func TestIntegration_OpenSearchProvisioner_MaskedFields(t *testing.T) {
	p, backend := setupOpenSearchProvisioner(t)

	const rawEmail = "alice@example.com"
	osSeed(t, backend, "mask-2026", `{"email":"`+rawEmail+`"}`)

	spec := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{
				IndexPatterns:  []string{"mask-*"},
				AllowedActions: []string{"read"},
				// Mask the base field; the keyword doc-values used by the
				// aggregation below are masked as a result.
				MaskedFields: []string{"email"},
			},
		},
	}
	user, pass, err := p.EnsureUser(context.Background(), "mask@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { deleteOpenSearchUser(t, backend, user) })

	// Admin sees the raw email value in the aggregation bucket.
	if got := osTermsAggKey(t, backend, "mask-2026", "email.keyword",
		testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword); got != rawEmail {
		t.Fatalf("admin agg key = %q, want raw email %q", got, rawEmail)
	}

	// The masking user sees a masked (hashed) value, not the raw email.
	got := osTermsAggKey(t, backend, "mask-2026", "email.keyword", user, pass)
	if got == "" {
		t.Fatalf("masking user agg key missing")
	}
	if got == rawEmail {
		t.Fatalf("masking user should not see the raw email value %q", rawEmail)
	}
}
