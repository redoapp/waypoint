package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
)

type k8sTestAuthorizer struct {
	result *auth.AuthResult
	err    error
}

type k8sFuncAuthorizer func(context.Context, string, string) (*auth.AuthResult, error)

func (f k8sFuncAuthorizer) Authorize(ctx context.Context, remote, backend string) (*auth.AuthResult, error) {
	return f(ctx, remote, backend)
}

func (a k8sTestAuthorizer) Authorize(context.Context, string, string) (*auth.AuthResult, error) {
	return a.result, a.err
}

func k8sAuthResult(t *testing.T, groups ...string) *auth.AuthResult {
	t.Helper()
	return &auth.AuthResult{
		LoginName: "alice@example.com",
		NodeName:  "alice-laptop",
		MatchedRules: []auth.CapRule{{
			Backends: map[string]auth.BackendCap{
				"eks-prod": {
					K8s: &auth.K8sCap{
						Impersonate: &auth.K8sImpersonateRule{Groups: groups},
					},
				},
			},
		}},
	}
}

func startK8sProxy(t *testing.T, backendURL string, backendTLS bool, authResult *auth.AuthResult, authErr error) string {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "k8stest:", m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := restrict.NewTracker(store, m, logger)

	p := &KubernetesProxy{
		Backend:      strings.TrimPrefix(strings.TrimPrefix(backendURL, "https://"), "http://"),
		Name:         "eks-prod",
		Auth:         k8sTestAuthorizer{result: authResult, err: authErr},
		Tracker:      tracker,
		Metrics:      m,
		KubeConfig:   &config.KubernetesAdmin{Token: "waypoint-sa-token"},
		BackendTLS:   backendTLS,
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}
	if backendTLS {
		p.KubeConfig.InsecureSkipVerify = true
	}
	if err := p.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()
	return ln.Addr().String()
}

func TestKubernetesBackendURL(t *testing.T) {
	u, err := kubernetesBackendURL("10.0.0.1:6443", true)
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://10.0.0.1:6443" {
		t.Fatalf("got %s", u)
	}
	u, err = kubernetesBackendURL("http://127.0.0.1:8080", false)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" || u.Host != "127.0.0.1:8080" {
		t.Fatalf("got %s", u)
	}
}

func TestStripImpersonationHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer stolen")
	h.Set("Impersonate-User", "cluster-admin")
	h.Add("Impersonate-Group", "system:masters")
	h.Set("Impersonate-Uid", "0")
	h.Set("Impersonate-Extra-node", "evil")
	h.Set("Accept", "application/json")
	stripImpersonationHeaders(h)
	if h.Get("Impersonate-User") != "" || h.Get("Impersonate-Group") != "" || h.Get("Impersonate-Uid") != "" || h.Get("Impersonate-Extra-node") != "" {
		t.Fatalf("impersonation headers survived: %v", h)
	}
	if h.Get("Accept") != "application/json" {
		t.Fatal("lost unrelated header")
	}
}

func TestKubernetesProxy_ImpersonatesUserAndGroups(t *testing.T) {
	var gotUser, gotAuth string
	var gotGroups []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("Impersonate-User")
		gotAuth = r.Header.Get("Authorization")
		gotGroups = r.Header.Values("Impersonate-Group")
		if r.URL.Path != "/api/v1/namespaces/default/pods" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"PodList","items":[]}`)
	}))
	t.Cleanup(backend.Close)

	addr := startK8sProxy(t, backend.URL, false, k8sAuthResult(t, "waypoint:readonly", "system:authenticated"), nil)
	resp, err := http.Get("http://" + addr + "/api/v1/namespaces/default/pods")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if gotUser != "alice@example.com" {
		t.Errorf("Impersonate-User = %q", gotUser)
	}
	if gotAuth != "Bearer waypoint-sa-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if strings.Join(gotGroups, ",") != "waypoint:readonly,system:authenticated" {
		t.Errorf("groups = %v", gotGroups)
	}
}

func TestKubernetesProxy_StripsClientImpersonation(t *testing.T) {
	var gotUser string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("Impersonate-User")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	addr := startK8sProxy(t, backend.URL, false, k8sAuthResult(t), nil)
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Impersonate-User", "system:masters")
	req.Header.Set("Impersonate-Group", "system:masters")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotUser != "alice@example.com" {
		t.Fatalf("client impersonation was not replaced, got %q", gotUser)
	}
}

func TestKubernetesProxy_AuthFailureForbidden(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("backend should not be reached")
	}))
	t.Cleanup(backend.Close)

	addr := startK8sProxy(t, backend.URL, false, nil, errors.New("not authorized for backend"))
	resp, err := http.Get("http://" + addr + "/api")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestKubernetesProxy_AuthenticatesEveryRequest(t *testing.T) {
	var calls atomic.Int64
	p := &KubernetesProxy{
		Name:    "eks-prod",
		Metrics: metrics.Noop(),
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth: k8sFuncAuthorizer(func(context.Context, string, string) (*auth.AuthResult, error) {
			if calls.Add(1) == 1 {
				return k8sAuthResult(t, "readers"), nil
			}
			return nil, errors.New("revoked")
		}),
	}
	nextCalls := 0
	handler := p.requestAuthorizer("100.64.0.1:1234", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalls++
		w.WriteHeader(http.StatusOK)
	}), p.Logger)

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api", nil))
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api", nil))

	if first.Code != http.StatusOK || second.Code != http.StatusForbidden {
		t.Fatalf("status codes = %d, %d", first.Code, second.Code)
	}
	if calls.Load() != 2 || nextCalls != 1 {
		t.Fatalf("auth calls = %d, next calls = %d", calls.Load(), nextCalls)
	}
}

func TestKubernetesProxy_WatchFlushes(t *testing.T) {
	started := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("backend ResponseWriter is not a Flusher")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		close(started)
		_, _ = io.WriteString(w, "{\"type\":\"ADDED\"}\n")
		flusher.Flush()
	}))
	t.Cleanup(backend.Close)

	addr := startK8sProxy(t, backend.URL, false, k8sAuthResult(t), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/api/v1/pods?watch=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("watch did not start")
	}
	buf := make([]byte, 64)
	n, err := resp.Body.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("read watch body: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "ADDED") {
		t.Fatalf("body %q", buf[:n])
	}
}

func TestKubernetesProxy_UpstreamUsesHTTP1(t *testing.T) {
	var protoMajor int
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protoMajor = r.ProtoMajor
		w.WriteHeader(http.StatusOK)
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	t.Cleanup(backend.Close)

	addr := startK8sProxy(t, backend.URL, true, k8sAuthResult(t), nil)
	resp, err := http.Get("http://" + addr + "/version")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if protoMajor != 1 {
		t.Fatalf("upstream HTTP version = %d, want HTTP/1.1", protoMajor)
	}
}

func TestKubernetesProxy_TokenFile(t *testing.T) {
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	tokenPath := t.TempDir() + "/token"
	if err := os.WriteFile(tokenPath, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	m := metrics.Noop()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := restrict.NewTracker(restrict.NewRedisStore(rdb, "k8stest:", m), m, logger)

	p := &KubernetesProxy{
		Backend:    strings.TrimPrefix(backend.URL, "http://"),
		Name:       "eks-prod",
		Auth:       k8sTestAuthorizer{result: k8sAuthResult(t)},
		Tracker:    tracker,
		Metrics:    m,
		KubeConfig: &config.KubernetesAdmin{TokenFile: tokenPath},
		Logger:     logger,
	}
	if err := p.Prepare(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p.HandleConn(context.Background(), conn)
	}()

	resp, err := http.Get("http://" + ln.Addr().String() + "/version")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer file-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}
