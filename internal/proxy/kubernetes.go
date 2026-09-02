package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"k8s.io/client-go/rest"
	k8stransport "k8s.io/client-go/transport"

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
	Backend       string
	Name          string
	Auth          Authorizer
	Tracker       *restrict.Tracker
	Metrics       *metrics.Metrics
	KubeConfig    *config.KubernetesAdmin
	ClientTLSMode config.TLSMode
	ClientTLS     *tls.Config
	BackendTLS    bool
	Logger        *slog.Logger
	Dialer        func(ctx context.Context, network, addr string) (net.Conn, error)
	BytesRead     *atomic.Int64
	BytesWritten  *atomic.Int64
	FlushInterval time.Duration // 0 means flush immediately (watches)
	backendURL    *url.URL
	transport     http.RoundTripper
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

	restConfig := &rest.Config{
		Host:            u.String(),
		BearerToken:     strings.TrimSpace(p.KubeConfig.Token),
		BearerTokenFile: p.KubeConfig.TokenFile,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile:   p.KubeConfig.CAFile,
			Insecure: p.KubeConfig.InsecureSkipVerify,
		},
		Dial: p.Dialer,
	}
	transportConfig, err := restConfig.TransportConfig()
	if err != nil {
		return fmt.Errorf("create kubernetes transport config: %w", err)
	}
	tlsConfig, err := k8stransport.TLSConfigFor(transportConfig)
	if err != nil {
		return fmt.Errorf("create kubernetes TLS config: %w", err)
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = tlsConfig
	base.ForceAttemptHTTP2 = false
	// Kubernetes SPDY streaming is incompatible with HTTP/2. Match the
	// official Tailscale API proxy and force HTTP/1.1 upstream.
	base.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	if p.Dialer != nil {
		base.DialContext = p.Dialer
	}
	p.transport, err = k8stransport.HTTPWrappersForConfig(transportConfig, base)
	if err != nil {
		return fmt.Errorf("wrap kubernetes transport: %w", err)
	}
	return nil
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

	setupSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	setupSpan.End()

	cl := p.Tracker.WrapConn(ctx, result.LoginName, result.Limits, p.Name)
	cl.Start()
	defer cl.Stop()

	counted := &countingConn{Conn: clientConn, cl: cl}

	handler := p.requestAuthorizer(counted.RemoteAddr().String(), p.apiHandler(log), log)
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

type kubernetesIdentityKey struct{}

func (p *KubernetesProxy) requestAuthorizer(remoteAddr string, next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := p.Metrics
		listenerAttr := metrics.AttrListener.String(p.Name)
		m.RevalAttempts.Add(r.Context(), 1, m.Attrs("waypoint.reval.attempts", listenerAttr))

		result, err := p.Auth.Authorize(r.Context(), remoteAddr, p.Name)
		if err != nil {
			m.RevalFailures.Add(r.Context(), 1, m.Attrs("waypoint.reval.failures", listenerAttr))
			log.WarnContext(r.Context(), "request authentication failed", "error", err)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ident := auth.KubernetesIdentityFrom(result, p.Name)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), kubernetesIdentityKey{}, ident)))
	})
}

func (p *KubernetesProxy) reverseProxy(log *slog.Logger) http.Handler {
	flush := p.FlushInterval
	if flush == 0 {
		flush = -1
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(p.backendURL)
			r.Out.Host = p.backendURL.Host
			r.Out.Header.Del("Authorization")
			stripImpersonationHeaders(r.Out.Header)
			ident, _ := r.Out.Context().Value(kubernetesIdentityKey{}).(auth.KubernetesIdentity)
			applyImpersonation(r.Out.Header, ident)
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

// apiHandler keeps streaming subresources explicit, as the official Tailscale
// proxy does. They currently share the standard upgrade-capable reverse proxy;
// separate routes leave room for session recording without changing REST
// request behavior.
func (p *KubernetesProxy) apiHandler(log *slog.Logger) http.Handler {
	rp := p.reverseProxy(log)
	mux := http.NewServeMux()
	for _, pattern := range []string{
		"GET /api/v1/namespaces/{namespace}/pods/{pod}/exec",
		"POST /api/v1/namespaces/{namespace}/pods/{pod}/exec",
		"GET /api/v1/namespaces/{namespace}/pods/{pod}/attach",
		"POST /api/v1/namespaces/{namespace}/pods/{pod}/attach",
		"GET /api/v1/namespaces/{namespace}/pods/{pod}/portforward",
		"POST /api/v1/namespaces/{namespace}/pods/{pod}/portforward",
	} {
		mux.Handle(pattern, rp)
	}
	mux.Handle("/", rp)
	return mux
}

func applyImpersonation(h http.Header, ident auth.KubernetesIdentity) {
	if ident.User != "" {
		h.Set("Impersonate-User", ident.User)
	}
	for _, g := range ident.Groups {
		h.Add("Impersonate-Group", g)
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
