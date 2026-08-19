//go:build integration

package provision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/redoapp/waypoint/internal/testutil"
)

const (
	sigTestAKID    = "AKIDINTEGRATIONTEST"
	sigTestSecret  = "integration/test/secret/key/AWSExampleValue001"
	sigTestRegion  = "us-east-1"
	sigTestService = "es"
)

// parseSignedHeaders extracts the SignedHeaders list from a SigV4 Authorization
// header value.
func parseSignedHeaders(authz string) []string {
	for _, part := range strings.Split(authz, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "SignedHeaders=") {
			return strings.Split(strings.TrimPrefix(part, "SignedHeaders="), ";")
		}
	}
	return nil
}

// verifyIncomingSigV4 independently validates the SigV4 signature on an inbound
// request by reconstructing the request from only its signed headers and
// re-signing with the shared test credentials at the request's own timestamp,
// then comparing the resulting Authorization header. A match proves the
// signature covers the method, path, query, signed headers, and body.
func verifyIncomingSigV4(r *http.Request, body []byte) error {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") {
		return fmt.Errorf("missing SigV4 Authorization: %q", authz)
	}
	if !strings.Contains(authz, "/"+sigTestRegion+"/"+sigTestService+"/aws4_request") {
		return fmt.Errorf("wrong credential scope: %q", authz)
	}
	amzDate := r.Header.Get("X-Amz-Date")
	ts, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return fmt.Errorf("parse X-Amz-Date %q: %w", amzDate, err)
	}

	fresh, err := http.NewRequest(r.Method, "http://"+r.Host+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rebuild request: %w", err)
	}
	for _, h := range parseSignedHeaders(authz) {
		if h == "host" {
			continue
		}
		fresh.Header.Set(h, r.Header.Get(h))
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}

	creds, err := credentials.NewStaticCredentialsProvider(sigTestAKID, sigTestSecret, "").Retrieve(context.Background())
	if err != nil {
		return err
	}
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, fresh, payloadHash, sigTestService, sigTestRegion, ts); err != nil {
		return fmt.Errorf("re-sign: %w", err)
	}
	if fresh.Header.Get("Authorization") != authz {
		return fmt.Errorf("signature mismatch:\n got  %s\n want %s", authz, fresh.Header.Get("Authorization"))
	}
	return nil
}

// newSigV4VerifyingProxy fronts the real OpenSearch backend with a proxy that
// requires a valid SigV4 signature (as Amazon OpenSearch Service would), then
// re-authenticates to the backend as the admin internal user. It records how
// many signed requests it verified.
func newSigV4VerifyingProxy(t *testing.T, backend string, verified *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()

		if err := verifyIncomingSigV4(r, body); err != nil {
			http.Error(w, "signature verification failed: "+err.Error(), http.StatusForbidden)
			return
		}
		*verified++

		fwd, err := http.NewRequest(r.Method, "http://"+backend+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fwd.Header.Set("Content-Type", "application/json")
		fwd.SetBasicAuth(testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword)
		resp, err := http.DefaultClient.Do(fwd)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
}

// TestIntegration_OpenSearchProvisioner_SigV4EndToEnd proves the AWS IAM path:
// the provisioner signs its Security-API calls with SigV4, an independent
// verifier validates each signature against the shared test credentials, and the
// request reaches a real OpenSearch backend which creates the role and user. It
// then confirms the provisioned credentials authenticate against the backend.
func TestIntegration_OpenSearchProvisioner_SigV4EndToEnd(t *testing.T) {
	backend := testutil.OpenSearchBackend(t)

	var verified int
	proxy := newSigV4VerifyingProxy(t, backend, &verified)
	defer proxy.Close()
	proxyHost := strings.TrimPrefix(proxy.URL, "http://")

	sigAuth := &sigv4Authenticator{
		creds:   credentials.NewStaticCredentialsProvider(sigTestAKID, sigTestSecret, ""),
		signer:  v4.NewSigner(),
		region:  sigTestRegion,
		service: sigTestService,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// No admin user/password: authentication is entirely via SigV4.
	p := NewOpenSearchProvisioner("", "", proxyHost, "wp_os_", "sigv4", false, nil, logger, nil,
		WithOpenSearchAuthenticator(sigAuth))

	spec := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro", "cluster_monitor"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"logs-*"}, AllowedActions: []string{"read"}},
		},
	}

	user, pass, err := p.EnsureUser(context.Background(), "iam@example.com", "test-node", spec)
	if err != nil {
		t.Fatalf("EnsureUser over SigV4: %v", err)
	}
	t.Cleanup(func() {
		req, _ := http.NewRequest(http.MethodDelete,
			"http://"+backend+"/_plugins/_security/api/internalusers/"+url.PathEscape(user), nil)
		req.SetBasicAuth(testutil.OpenSearchAdminUser, testutil.OpenSearchAdminPassword)
		if resp, derr := http.DefaultClient.Do(req); derr == nil {
			resp.Body.Close()
		}
	})

	// The proxy must have verified at least the role PUT and the user PUT.
	if verified < 2 {
		t.Fatalf("verified SigV4 requests = %d, want >= 2", verified)
	}

	// The provisioned internal user (created via the signed calls) must exist
	// and authenticate against the real backend.
	status, body := osRequest(t, backend, http.MethodGet, "/_cluster/health", user, pass, nil)
	if status != http.StatusOK {
		t.Fatalf("provisioned (SigV4) user health status = %d: %s", status, body)
	}
}
