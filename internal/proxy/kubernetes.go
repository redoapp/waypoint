package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/logging"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
)

const impersonateExtraPrefix = "Impersonate-Extra-"

// KubernetesProxy is an HTTP reverse proxy for kube-apiserver. It authenticates
// the Tailscale peer, then impersonates that identity using Waypoint's own
// service-account (or token) credentials.
type KubernetesProxy struct {
	Backend          string
	Name             string
	Auth             Authorizer
	Tracker          *restrict.Tracker
	Metrics          *metrics.Metrics
	KubeConfig       *config.KubernetesAdmin
	ClientTLSMode    config.TLSMode
	ClientTLS        *tls.Config
	BackendTLS       bool
	BackendTLSConfig *tls.Config
	RevalInterval    time.Duration
	Logger           *slog.Logger
	Dialer           func(ctx context.Context, network, addr string) (net.Conn, error)
	BytesRead        *atomic.Int64
	BytesWritten     *atomic.Int64
	FlushInterval    time.Duration // 0 means flush immediately (watches)
	backendURL       *url.URL
	transport        http.RoundTripper
}

// Prepare parses the backend URL and builds the apiserver transport.
func (p *KubernetesProxy) Prepare() error {
	if p.KubeConfig == nil {
		return errors.New("kubernetes listener requires [listeners.kubernetes] config")
	}
	u, err := kubernetesBackendURL(p.Backend, p.BackendTLS)
	if err != nil {
		return err
	}
	p.backendURL = u

	tlsConf := p.BackendTLSConfig
	if tlsConf == nil && p.BackendTLS {
		loaded, err := LoadKubernetesBackendTLS(p.KubeConfig)
		if err != nil {
			return err
		}
		tlsConf = loaded
		p.BackendTLSConfig = tlsConf
	}

	dial := p.Dialer
	p.transport = &http.Transport{
		TLSClientConfig:   tlsConf,
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if dial != nil {
				return dial(ctx, network, addr)
			}
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
	return nil
}

// LoadKubernetesBackendTLS builds the TLS config used to reach kube-apiserver.
func LoadKubernetesBackendTLS(k *config.KubernetesAdmin) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	if k != nil && k.InsecureSkipVerify {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	if k == nil || strings.TrimSpace(k.CAFile) == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(k.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read kubernetes ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("kubernetes ca_file %q contains no certificates", k.CAFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

func kubernetesBackendURL(backend string, useTLS bool) (*url.URL, error) {
	backend = strings.TrimSpace(backend)
	if backend == "" {
		return nil, errors.New("kubernetes backend is required")
	}
	if strings.Contains(backend, "://") {
		return url.Parse(backend)
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return url.Parse(scheme + "://" + backend)
}

// HandleConn processes a single inbound connection from kubectl or another
// Kubernetes API client.
func (p *KubernetesProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	connID := logging.NewConnID()
	log := p.Logger.With("conn_id", connID, "remote", clientConn.RemoteAddr())
	log.DebugContext(ctx, "connection accepted")

	m := p.Metrics
	tracer := m.Tracer()
	listenerAttr := metrics.AttrListener.String(p.Name)
	modeAttr := metrics.AttrMode.String("kubernetes")

	ctx, setupSpan := tracer.Start(ctx, "waypoint.connection.setup",
		trace.WithAttributes(
			attribute.String("waypoint.conn_id", connID),
			attribute.String("waypoint.listener", p.Name),
			attribute.String("waypoint.mode", "kubernetes"),
			attribute.String("waypoint.backend", p.Backend),
		),
	)
	setupSpanCtx := setupSpan.SpanContext()

	if p.ClientTLS != nil && p.ClientTLSMode != config.TLSOff {
		tlsConn := tls.Server(clientConn, p.ClientTLS)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			if isBenignDisconnect(err) {
				recordSetupFailure(ctx, log, m, setupSpan, err, "client TLS handshake failed", "client TLS handshake failed", p.Name, "kubernetes")
			} else {
				setupSpan.RecordError(err)
				setupSpan.SetStatus(codes.Error, "client TLS handshake failed")
				setupSpan.End()
				log.WarnContext(ctx, "client TLS handshake failed", "error", err)
			}
			return
		}
		clientConn = tlsConn
	}

	m.AuthAttempts.Add(ctx, 1, m.Attrs("waypoint.auth.attempts", listenerAttr))
	ctx, authSpan := tracer.Start(ctx, "waypoint.auth")
	authStart := time.Now()
	result, err := p.Auth.Authorize(ctx, clientConn.RemoteAddr().String(), p.Name)
	authDur := time.Since(authStart).Seconds()
	m.AuthLatency.Record(ctx, authDur, m.Attrs("waypoint.auth.latency", listenerAttr))

	var release func()
	if err != nil {
		authSpan.RecordError(err)
		authSpan.SetStatus(codes.Error, "auth failed")
		authSpan.End()
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "auth failed")
		setupSpan.End()
		m.AuthFailures.Add(ctx, 1, m.Attrs("waypoint.auth.failures", listenerAttr))
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		log.WarnContext(ctx, "auth failed", "error", err, "listener", p.Name)
		_ = serveHTTPOnConn(ctx, clientConn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
		}))
		return
	}
	authSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	authSpan.End()

	log.InfoContext(ctx, "authorized",
		"user", result.LoginName,
		"node", result.NodeName,
		"backend", p.Name,
	)

	ctx, slotSpan := tracer.Start(ctx, "waypoint.acquire_slot")
	release, err = p.Tracker.Acquire(ctx, result.LoginName, result.Limits, p.Name)
	if err != nil {
		slotSpan.RecordError(err)
		slotSpan.SetStatus(codes.Error, "limit exceeded")
		slotSpan.End()
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "limit exceeded")
		setupSpan.End()
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		log.WarnContext(ctx, "limit exceeded", "user", result.LoginName, "error", err)
		_ = serveHTTPOnConn(ctx, clientConn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "connection limit exceeded", http.StatusTooManyRequests)
		}))
		return
	}
	slotSpan.End()
	defer release()

	connStart := time.Now()
	m.ConnTotal.Add(ctx, 1, m.Attrs("waypoint.conn.total", listenerAttr, modeAttr))
	m.ConnActive.Add(ctx, 1, m.Attrs("waypoint.conn.active", listenerAttr, modeAttr))
	defer func() {
		m.ConnActive.Add(ctx, -1, m.Attrs("waypoint.conn.active", listenerAttr, modeAttr))
		m.ConnDuration.Record(ctx, time.Since(connStart).Seconds(),
			m.Attrs("waypoint.conn.duration", listenerAttr, metrics.AttrUser.String(result.LoginName)))
	}()

	ident := auth.KubernetesIdentityFrom(result, p.Name)
	state := &k8sConnState{ident: ident}

	setupSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	setupSpan.End()

	cl := p.Tracker.WrapConn(ctx, result.LoginName, result.Limits, p.Name)
	cl.Start()
	defer cl.Stop()

	counted := &countingConn{Conn: clientConn, cl: cl}

	revalCtx, revalCancel := context.WithCancel(ctx)
	defer revalCancel()
	if p.RevalInterval > 0 {
		go p.revalidateLoop(revalCtx, setupSpanCtx, connID, counted, result.LoginName, state, log)
	}

	handler := p.reverseProxy(state, log)
	serveErr := serveHTTPOnConn(ctx, counted, handler)
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !isBenignDisconnect(serveErr) {
		log.WarnContext(ctx, "http serve ended", "error", serveErr)
	}

	br, bw := cl.BytesRead(), cl.BytesWritten()
	if p.BytesRead != nil {
		p.BytesRead.Add(br)
	}
	if p.BytesWritten != nil {
		p.BytesWritten.Add(bw)
	}

	_, closeSpan := tracer.Start(ctx, "waypoint.connection.close",
		trace.WithLinks(trace.Link{SpanContext: setupSpanCtx}),
		trace.WithAttributes(
			attribute.String("waypoint.conn_id", connID),
			attribute.String("waypoint.listener", p.Name),
			attribute.String("waypoint.user", result.LoginName),
			attribute.Int64("waypoint.bytes_read", br),
			attribute.Int64("waypoint.bytes_written", bw),
			attribute.Float64("waypoint.duration_s", time.Since(connStart).Seconds()),
		),
	)
	closeSpan.End()

	log.InfoContext(ctx, "connection closed",
		"duration", time.Since(connStart),
		"bytes_read", br,
		"bytes_written", bw,
	)
}

type k8sConnState struct {
	mu    sync.Mutex
	ident auth.KubernetesIdentity
}

func (s *k8sConnState) snapshot() auth.KubernetesIdentity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ident
}

func (s *k8sConnState) set(ident auth.KubernetesIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ident = ident
}

func (p *KubernetesProxy) reverseProxy(state *k8sConnState, log *slog.Logger) http.Handler {
	flush := p.FlushInterval
	if flush == 0 {
		flush = -1
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(p.backendURL)
			r.Out.Host = p.backendURL.Host
			stripImpersonationHeaders(r.Out.Header)
			token, err := p.bearerToken()
			if err != nil {
				log.Error("kubernetes token unavailable", "error", err)
				return
			}
			r.Out.Header.Set("Authorization", "Bearer "+token)
			if p.KubeConfig.EffectiveImpersonate() {
				applyImpersonation(r.Out.Header, state.snapshot())
			}
		},
		Transport:     p.transport,
		FlushInterval: flush,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Warn("kubernetes backend request failed", "path", r.URL.Path, "error", err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return rp
}

func (p *KubernetesProxy) bearerToken() (string, error) {
	if p.KubeConfig == nil {
		return "", errors.New("no kubernetes config")
	}
	if t := strings.TrimSpace(p.KubeConfig.Token); t != "" {
		return t, nil
	}
	if p.KubeConfig.TokenFile == "" {
		return "", errors.New("no kubernetes token configured")
	}
	b, err := os.ReadFile(p.KubeConfig.TokenFile)
	if err != nil {
		return "", fmt.Errorf("read kubernetes token_file: %w", err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", errors.New("kubernetes token_file is empty")
	}
	return t, nil
}

func (p *KubernetesProxy) revalidateLoop(ctx context.Context, setupSpanCtx trace.SpanContext, connID string, clientConn net.Conn, loginName string, state *k8sConnState, log *slog.Logger) {
	ticker := time.NewTicker(p.RevalInterval)
	defer ticker.Stop()

	m := p.Metrics
	tracer := m.Tracer()
	listenerAttr := metrics.AttrListener.String(p.Name)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.DebugContext(ctx, "revalidation check")
			m.RevalAttempts.Add(ctx, 1, m.Attrs("waypoint.reval.attempts", listenerAttr))

			_, revalSpan := tracer.Start(ctx, "waypoint.revalidation",
				trace.WithLinks(trace.Link{SpanContext: setupSpanCtx}),
				trace.WithAttributes(
					attribute.String("waypoint.conn_id", connID),
					attribute.String("waypoint.listener", p.Name),
					attribute.String("waypoint.user", loginName),
				),
			)

			revalResult, err := p.Auth.Authorize(ctx, clientConn.RemoteAddr().String(), p.Name)
			if err != nil {
				revalSpan.RecordError(err)
				revalSpan.SetStatus(codes.Error, "revalidation failed")
				revalSpan.End()
				m.RevalFailures.Add(ctx, 1, m.Attrs("waypoint.reval.failures", listenerAttr))
				log.WarnContext(ctx, "revalidation failed, closing connection",
					"user", loginName,
					"error", err,
				)
				clientConn.Close()
				return
			}
			state.set(auth.KubernetesIdentityFrom(revalResult, p.Name))
			revalSpan.End()
			log.DebugContext(ctx, "revalidation passed")
		}
	}
}

func applyImpersonation(h http.Header, ident auth.KubernetesIdentity) {
	if ident.User != "" {
		h.Set("Impersonate-User", ident.User)
	}
	for _, g := range ident.Groups {
		h.Add("Impersonate-Group", g)
	}
	for key, values := range ident.Extra {
		header := impersonateExtraPrefix + key
		for _, v := range values {
			h.Add(header, v)
		}
	}
}

func stripImpersonationHeaders(h http.Header) {
	h.Del("Impersonate-User")
	h.Del("Impersonate-Group")
	h.Del("Impersonate-Uid")
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), impersonateExtraPrefix) ||
			strings.HasPrefix(strings.ToLower(k), strings.ToLower(impersonateExtraPrefix)) {
			h.Del(k)
		}
	}
}

type countingConn struct {
	net.Conn
	cl *restrict.ConnLimits
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if rerr := c.cl.ReportRead(int64(n)); rerr != nil {
			_ = c.Conn.Close()
			if err == nil {
				err = rerr
			}
		}
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		if rerr := c.cl.ReportWrite(int64(n)); rerr != nil {
			_ = c.Conn.Close()
			if err == nil {
				err = rerr
			}
		}
	}
	return n, err
}

type oneShotListener struct {
	conn   net.Conn
	addr   net.Addr
	first  sync.Once
	closed chan struct{}
	once   sync.Once
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	return &oneShotListener{
		conn:   conn,
		addr:   conn.LocalAddr(),
		closed: make(chan struct{}),
	}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	served := false
	var c net.Conn
	l.first.Do(func() {
		c = l.conn
		served = true
	})
	if served {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneShotListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.addr
}

func serveHTTPOnConn(ctx context.Context, conn net.Conn, handler http.Handler) error {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	ln := newOneShotListener(conn)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if err != nil && !isBenignDisconnect(err) && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
