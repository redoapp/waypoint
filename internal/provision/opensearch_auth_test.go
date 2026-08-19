package provision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func testSigV4Authenticator() *sigv4Authenticator {
	return &sigv4Authenticator{
		creds:   credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""),
		signer:  v4.NewSigner(),
		region:  "us-east-1",
		service: "es",
	}
}

func TestSigV4Authenticator_SignsRequest(t *testing.T) {
	a := testSigV4Authenticator()
	body := []byte(`{"password":"secret","opendistro_security_roles":["wp_os_role_abc"]}`)
	req, err := http.NewRequest(http.MethodPut,
		"https://search-example.us-east-1.es.amazonaws.com/_plugins/_security/api/internalusers/wp_os_alice",
		bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := a.Authenticate(context.Background(), req, body); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	authz := req.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("Authorization not SigV4: %q", authz)
	}
	// Credential scope must be <akid>/<date>/<region>/<service>/aws4_request.
	if !strings.Contains(authz, "Credential=AKIDEXAMPLE/") ||
		!strings.Contains(authz, "/us-east-1/es/aws4_request") {
		t.Fatalf("credential scope wrong: %q", authz)
	}
	// Host and the AWS control headers must be part of the signature.
	for _, h := range []string{"host", "x-amz-content-sha256", "x-amz-date"} {
		if !strings.Contains(authz, h) {
			t.Fatalf("SignedHeaders missing %q: %q", h, authz)
		}
	}
	if !strings.Contains(authz, "Signature=") {
		t.Fatalf("no Signature in %q", authz)
	}

	if req.Header.Get("X-Amz-Date") == "" {
		t.Fatal("X-Amz-Date not set")
	}
	sum := sha256.Sum256(body)
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("X-Amz-Content-Sha256 = %q, want body hash", got)
	}
	// Basic auth must not be present when signing with IAM.
	if _, _, ok := req.BasicAuth(); ok {
		t.Fatal("SigV4 request must not carry Basic auth")
	}
}

func TestSigV4Authenticator_EmptyBodyHash(t *testing.T) {
	a := testSigV4Authenticator()
	req, err := http.NewRequest(http.MethodGet,
		"https://search-example.us-east-1.es.amazonaws.com/_plugins/_security/api/roles/wp_os_role_abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Authenticate(context.Background(), req, nil); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	emptyHash := sha256.Sum256(nil)
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != hex.EncodeToString(emptyHash[:]) {
		t.Fatalf("empty-body content hash = %q, want %q", got, hex.EncodeToString(emptyHash[:]))
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		t.Fatal("bodyless request not signed")
	}
}

func TestBasicAuthenticator_SetsBasicAuth(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "http://os.internal:9200/_plugins/_security/api/roles/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := (basicAuthenticator{user: "admin", pass: "adminpass"}).Authenticate(context.Background(), req, nil); err != nil {
		t.Fatal(err)
	}
	user, pass, ok := req.BasicAuth()
	if !ok || user != "admin" || pass != "adminpass" {
		t.Fatalf("basic auth = %q/%q ok=%v", user, pass, ok)
	}
}

// TestNewOpenSearchProvisioner_DefaultAndOverrideAuth verifies the provisioner
// defaults to Basic auth and that WithOpenSearchAuthenticator overrides it.
func TestNewOpenSearchProvisioner_DefaultAndOverrideAuth(t *testing.T) {
	p := newOpenSearchTestProvisioner("os.internal:9200", false)
	if _, ok := p.auth.(basicAuthenticator); !ok {
		t.Fatalf("default authenticator = %T, want basicAuthenticator", p.auth)
	}

	sig := testSigV4Authenticator()
	p2 := NewOpenSearchProvisioner("admin", "adminpass", "os.internal:9200", "wp_os_", "svc", false, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, WithOpenSearchAuthenticator(sig))
	if p2.auth != sig {
		t.Fatalf("WithOpenSearchAuthenticator did not override auth: got %T", p2.auth)
	}
}
