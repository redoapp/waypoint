package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/restrict"
)

const defaultOpenSearchCacheTTL = 30 * time.Second

// OpenSearchProxy handles HTTP-aware OpenSearch proxying with Tailscale auth,
// backend credential provisioning, connection limits, and revalidation.
type OpenSearchProxy struct {
	Backend          string
	Name             string
	AdvertiseAddr    string
	Auth             Authorizer
	Tracker          *restrict.Tracker
	Provisioner      *provision.OpenSearchProvisioner
	Metrics          *metrics.Metrics
	OpenSearchConfig *config.OpenSearchAdmin
	ClientTLSMode    config.TLSMode
	ClientTLS        *tls.Config
	BackendTLS       bool
	RevalInterval    time.Duration
	CacheTTL         time.Duration
	Logger           *slog.Logger
	Dialer           func(ctx context.Context, network, addr string) (net.Conn, error)
	BytesRead        *atomic.Int64
	BytesWritten     *atomic.Int64

	cacheMu   sync.Mutex
	authCache map[string]cachedOpenSearchAuth
	credCache map[string]cachedOpenSearchCredential
}

type cachedOpenSearchAuth struct {
	result  *auth.AuthResult
	expires time.Time
}

type cachedOpenSearchCredential struct {
	username string
	password string
	expires  time.Time
}

type openSearchStaticCredential struct {
	Name     string
	Username string
	Password string
}

type missingOpenSearchStaticCredentialError struct {
	signature string
}

func (e *missingOpenSearchStaticCredentialError) Error() string {
	return "no static OpenSearch user matches grants " + e.signature
}

func (e *missingOpenSearchStaticCredentialError) ClientMessage() string {
	return "not authorized: no static OpenSearch user configured for requested permissions"
}

// HandleConn processes a single inbound OpenSearch HTTP connection.
func (p *OpenSearchProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	connID := logging.NewConnID()
	log := p.Logger.With("conn_id", connID, "remote", clientConn.RemoteAddr())
	log.DebugContext(ctx, "connection accepted")

	clientConn, clientSNI, err := p.acceptClientTLS(clientConn)
	if err != nil {
		log.WarnContext(ctx, "client TLS failed", "error", err)
		return
	}
	if clientSNI != "" {
		log.DebugContext(ctx, "client TLS established", "sni", clientSNI)
	}

	m := p.Metrics
	tracer := m.Tracer()
	listenerAttr := metrics.AttrListener.String(p.Name)
	modeAttr := metrics.AttrMode.String("opensearch")

	ctx, setupSpan := tracer.Start(ctx, "waypoint.connection.setup",
		trace.WithAttributes(
			attribute.String("waypoint.conn_id", connID),
			attribute.String("waypoint.listener", p.Name),
			attribute.String("waypoint.mode", "opensearch"),
			attribute.String("waypoint.backend", p.Backend),
		),
	)
	setupSpanCtx := setupSpan.SpanContext()

	m.AuthAttempts.Add(ctx, 1, m.Attrs("waypoint.auth.attempts", listenerAttr))
	ctx, authSpan := tracer.Start(ctx, "waypoint.auth")
	authStart := time.Now()
	result, err := p.authorize(ctx, clientConn.RemoteAddr().String())
	authDur := time.Since(authStart).Seconds()
	m.AuthLatency.Record(ctx, authDur, m.Attrs("waypoint.auth.latency", listenerAttr))
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
		writeHTTPError(clientConn, http.StatusForbidden, "authentication failed")
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
	release, err := p.Tracker.Acquire(ctx, result.LoginName, result.Limits, p.Name)
	if err != nil {
		slotSpan.RecordError(err)
		slotSpan.SetStatus(codes.Error, "limit exceeded")
		slotSpan.End()
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "limit exceeded")
		setupSpan.End()
		m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
		log.WarnContext(ctx, "limit exceeded", "user", result.LoginName, "error", err)
		writeHTTPError(clientConn, http.StatusTooManyRequests, "too many connections")
		return
	}
	slotSpan.End()
	defer release()
	log.DebugContext(ctx, "connection slot acquired")

	connStart := time.Now()
	m.ConnTotal.Add(ctx, 1, m.Attrs("waypoint.conn.total", listenerAttr, modeAttr))
	m.ConnActive.Add(ctx, 1, m.Attrs("waypoint.conn.active", listenerAttr, modeAttr))
	defer func() {
		m.ConnActive.Add(ctx, -1, m.Attrs("waypoint.conn.active", listenerAttr, modeAttr))
		m.ConnDuration.Record(ctx, time.Since(connStart).Seconds(),
			m.Attrs("waypoint.conn.duration", listenerAttr, metrics.AttrUser.String(result.LoginName)))
	}()

	access, err := p.collectAccess(result)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "permissions failed")
		setupSpan.End()
		log.WarnContext(ctx, "no OpenSearch permissions", "user", result.LoginName, "error", err)
		writeHTTPError(clientConn, http.StatusForbidden, "not authorized")
		return
	}

	osUser, osPass, err := p.resolveBackendCredentials(ctx, result, access)
	if err != nil {
		var missingStatic *missingOpenSearchStaticCredentialError
		if errors.As(err, &missingStatic) {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "static credential missing")
			setupSpan.End()
			log.WarnContext(ctx, "static OpenSearch user missing",
				"user", result.LoginName,
				"signature", missingStatic.signature,
			)
			writeHTTPError(clientConn, http.StatusForbidden, missingStatic.ClientMessage())
			return
		}
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "credential resolution failed")
		setupSpan.End()
		log.ErrorContext(ctx, "credential resolution failed", "user", result.LoginName, "error", err)
		writeHTTPError(clientConn, http.StatusInternalServerError, "internal error")
		return
	}

	ctx, dialSpan := tracer.Start(ctx, "waypoint.dial_backend")
	var backendConn net.Conn
	if p.Dialer != nil {
		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		defer dialCancel()
		backendConn, err = p.Dialer(dialCtx, "tcp", p.Backend)
	} else {
		backendConn, err = net.DialTimeout("tcp", p.Backend, 10*time.Second)
	}
	if err != nil {
		dialSpan.RecordError(err)
		dialSpan.SetStatus(codes.Error, "dial failed")
		dialSpan.End()
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "dial failed")
		setupSpan.End()
		log.ErrorContext(ctx, "backend dial failed", "backend", p.Backend, "error", err)
		writeHTTPError(clientConn, http.StatusBadGateway, "backend unavailable")
		return
	}
	if p.BackendTLS {
		upgradedConn, err := upgradeOpenSearchBackendTLS(backendConn, p.Backend)
		if err != nil {
			backendConn.Close()
			dialSpan.RecordError(err)
			dialSpan.SetStatus(codes.Error, "backend TLS failed")
			dialSpan.End()
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "backend TLS failed")
			setupSpan.End()
			log.ErrorContext(ctx, "backend TLS failed", "backend", p.Backend, "error", err)
			writeHTTPError(clientConn, http.StatusBadGateway, "backend TLS failed")
			return
		}
		backendConn = upgradedConn
		log.DebugContext(ctx, "backend TLS established")
	}
	dialSpan.End()
	defer backendConn.Close()

	setupSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	setupSpan.End()

	cl := p.Tracker.WrapConn(ctx, result.LoginName, result.Limits, p.Name)
	cl.Start()
	defer cl.Stop()
	limitedClientConn := &openSearchLimitedConn{Conn: clientConn, limits: cl}

	revalCtx, revalCancel := context.WithCancel(ctx)
	defer revalCancel()
	if p.RevalInterval > 0 {
		go p.revalidateLoop(revalCtx, setupSpanCtx, connID, clientConn, backendConn, result.LoginName, log)
	}

	advertiseAddr := p.effectiveAdvertiseAddr(clientConn, clientSNI)
	relayResult := p.serveHTTPConnection(ctx, limitedClientConn, backendConn, osUser, osPass, advertiseAddr, log)

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
			attribute.String("waypoint.close_reason", string(relayResult.Reason)),
			attribute.String("waypoint.close_initiated_by", string(relayResult.InitiatedBy)),
		),
	)
	closeSpan.End()

	if relayResult.Reason != restrict.CloseNormal {
		log.WarnContext(ctx, "connection closed",
			"duration", time.Since(connStart),
			"bytes_read", br,
			"bytes_written", bw,
			"close_reason", relayResult.Reason,
			"initiated_by", relayResult.InitiatedBy,
			"error", relayResult.Err,
		)
		return
	}
	log.InfoContext(ctx, "connection closed",
		"duration", time.Since(connStart),
		"bytes_read", br,
		"bytes_written", bw,
		"close_reason", relayResult.Reason,
		"initiated_by", relayResult.InitiatedBy,
	)
}

func (p *OpenSearchProxy) serveHTTPConnection(ctx context.Context, clientConn net.Conn, backendConn net.Conn, backendUser, backendPass, advertiseAddr string, log *slog.Logger) restrict.RelayResult {
	clientReader := bufio.NewReader(clientConn)
	clientWriter := bufio.NewWriter(clientConn)
	backendReader := bufio.NewReader(backendConn)
	backendWriter := bufio.NewWriter(backendConn)

	for {
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			return openSearchRelayResult(restrict.DirClient, err)
		}

		closeAfterResponse := req.Close
		if err := prepareOpenSearchBackendRequest(req, p.Backend, p.BackendTLS, backendUser, backendPass); err != nil {
			req.Body.Close()
			writeHTTPError(clientWriter, http.StatusBadRequest, "bad request")
			clientWriter.Flush()
			return restrict.RelayResult{Reason: restrict.CloseNetwork, InitiatedBy: restrict.DirClient, Err: err}
		}

		if err := req.Write(backendWriter); err != nil {
			req.Body.Close()
			return openSearchRelayResult(restrict.DirClient, err)
		}
		req.Body.Close()
		if err := backendWriter.Flush(); err != nil {
			return openSearchRelayResult(restrict.DirClient, err)
		}

		resp, err := http.ReadResponse(backendReader, req)
		if err != nil {
			return openSearchRelayResult(restrict.DirBackend, err)
		}

		if shouldRewriteOpenSearchNodeInfo(req) {
			resp, err = rewriteOpenSearchNodeInfoResponse(resp, advertiseAddr)
			if err != nil {
				log.DebugContext(ctx, "node info rewrite skipped", "error", err)
			}
		}

		if resp.Close {
			closeAfterResponse = true
		}
		if err := resp.Write(clientWriter); err != nil {
			resp.Body.Close()
			return openSearchRelayResult(restrict.DirBackend, err)
		}
		resp.Body.Close()
		if err := clientWriter.Flush(); err != nil {
			return openSearchRelayResult(restrict.DirBackend, err)
		}
		if closeAfterResponse {
			return restrict.RelayResult{Reason: restrict.CloseNormal, InitiatedBy: restrict.DirClient}
		}
	}
}

func (p *OpenSearchProxy) collectAccess(result *auth.AuthResult) (provision.OpenSearchRoleSpec, error) {
	var combined provision.OpenSearchRoleSpec
	found := false
	for _, rule := range result.MatchedRules {
		backendCap, ok := rule.Backends[p.Name]
		if !ok || backendCap.OpenSearch == nil {
			continue
		}
		found = true
		spec, err := provision.ExpandOpenSearchPermissions(backendCap.OpenSearch)
		if err != nil {
			return provision.OpenSearchRoleSpec{}, err
		}
		combined.ClusterPermissions = append(combined.ClusterPermissions, spec.ClusterPermissions...)
		combined.IndexPermissions = append(combined.IndexPermissions, spec.IndexPermissions...)
		combined.TenantPermissions = append(combined.TenantPermissions, spec.TenantPermissions...)
	}
	if !found {
		return provision.OpenSearchRoleSpec{}, fmt.Errorf("no OpenSearch permissions")
	}
	spec := provision.NormalizeOpenSearchRoleSpec(combined)
	if provision.IsEmptyOpenSearchRoleSpec(spec) {
		return provision.OpenSearchRoleSpec{}, fmt.Errorf("no OpenSearch permissions")
	}
	return spec, nil
}

func (p *OpenSearchProxy) resolveBackendCredentials(ctx context.Context, result *auth.AuthResult, access provision.OpenSearchRoleSpec) (string, string, error) {
	signature := provision.OpenSearchRoleSignature(access)
	cacheKey := result.LoginName + "\x00" + result.NodeName + "\x00" + signature
	if cred, ok := p.getCachedCredential(cacheKey); ok {
		return cred.username, cred.password, nil
	}

	var username, password string
	switch p.OpenSearchConfig.EffectiveProvisionMode() {
	case config.OpenSearchProvisionStatic:
		cred, err := p.selectStaticCredential(access)
		if err != nil {
			return "", "", err
		}
		p.Logger.DebugContext(ctx, "static OpenSearch user selected",
			"static_user", cred.Name,
			"opensearch_user", cred.Username,
		)
		username, password = cred.Username, cred.Password
	case config.OpenSearchProvisionDatabase:
		if p.Provisioner == nil {
			return "", "", fmt.Errorf("opensearch provisioner is not configured")
		}
		m := p.Metrics
		listenerAttr := metrics.AttrListener.String(p.Name)
		tracer := m.Tracer()

		provStart := time.Now()
		m.ProvisionTotal.Add(ctx, 1, m.Attrs("waypoint.provision.total", listenerAttr))
		ctx, provSpan := tracer.Start(ctx, "waypoint.provision")
		var err error
		username, password, err = p.Provisioner.EnsureUser(ctx, result.LoginName, result.NodeName, access)
		provSpan.End()
		m.ProvisionLatency.Record(ctx, time.Since(provStart).Seconds(),
			m.Attrs("waypoint.provision.latency", listenerAttr))
		if err != nil {
			m.ProvisionErrors.Add(ctx, 1, m.Attrs("waypoint.provision.errors", listenerAttr))
			return "", "", fmt.Errorf("provision user: %w", err)
		}
		p.Logger.DebugContext(ctx, "user provisioned", "opensearch_user", username)
	default:
		return "", "", fmt.Errorf("unsupported opensearch provision mode %q", p.OpenSearchConfig.EffectiveProvisionMode())
	}

	p.setCachedCredential(cacheKey, cachedOpenSearchCredential{
		username: username,
		password: password,
		expires:  time.Now().Add(p.cacheTTL()),
	})
	return username, password, nil
}

func (p *OpenSearchProxy) selectStaticCredential(access provision.OpenSearchRoleSpec) (openSearchStaticCredential, error) {
	if p.OpenSearchConfig == nil || p.OpenSearchConfig.Provision == nil {
		return openSearchStaticCredential{}, fmt.Errorf("opensearch static provisioning is not configured")
	}
	want := provision.OpenSearchRoleSignature(access)
	for _, user := range p.OpenSearchConfig.Provision.StaticUsers {
		spec := openSearchStaticUserSpec(user)
		if provision.OpenSearchRoleSignature(spec) == want {
			return openSearchStaticCredential{
				Name:     openSearchStaticUserName(user),
				Username: user.Username,
				Password: user.Password,
			}, nil
		}
	}
	return openSearchStaticCredential{}, &missingOpenSearchStaticCredentialError{signature: want}
}

func openSearchStaticUserSpec(user config.OpenSearchStaticUser) provision.OpenSearchRoleSpec {
	spec := provision.OpenSearchRoleSpec{
		ClusterPermissions: append([]string{}, user.ClusterPermissions...),
	}
	for _, perm := range user.IndexPermissions {
		spec.IndexPermissions = append(spec.IndexPermissions, provision.OpenSearchIndexPermissionSpec{
			IndexPatterns:  append([]string{}, perm.IndexPatterns...),
			DLS:            perm.DLS,
			FLS:            append([]string{}, perm.FLS...),
			MaskedFields:   append([]string{}, perm.MaskedFields...),
			AllowedActions: append([]string{}, perm.AllowedActions...),
		})
	}
	for _, perm := range user.TenantPermissions {
		spec.TenantPermissions = append(spec.TenantPermissions, provision.OpenSearchTenantPermissionSpec{
			TenantPatterns: append([]string{}, perm.TenantPatterns...),
			AllowedActions: append([]string{}, perm.AllowedActions...),
		})
	}
	return provision.NormalizeOpenSearchRoleSpec(spec)
}

func openSearchStaticUserName(user config.OpenSearchStaticUser) string {
	if strings.TrimSpace(user.Name) != "" {
		return user.Name
	}
	return user.Username
}

func prepareOpenSearchBackendRequest(req *http.Request, backend string, backendTLS bool, backendUser, backendPass string) error {
	if req.URL == nil {
		return fmt.Errorf("request URL is nil")
	}
	req.RequestURI = ""
	if backendTLS {
		req.URL.Scheme = "https"
	} else {
		req.URL.Scheme = "http"
	}
	req.URL.Host = backend
	req.Host = backend
	req.RemoteAddr = ""

	removeHopByHopHeaders(req.Header)
	req.Header.Del("Authorization")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Accept-Encoding")
	req.SetBasicAuth(backendUser, backendPass)
	return nil
}

func removeHopByHopHeaders(header http.Header) {
	for _, token := range header.Values("Connection") {
		for _, name := range strings.Split(token, ",") {
			if name = strings.TrimSpace(name); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}

func shouldRewriteOpenSearchNodeInfo(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	path := strings.Trim(req.URL.Path, "/")
	if path == "_nodes" {
		return true
	}
	if !strings.HasPrefix(path, "_nodes/") {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return false
	}
	switch parts[1] {
	case "stats", "hot_threads", "usage", "reload_secure_settings":
		return false
	}
	return true
}

func rewriteOpenSearchNodeInfoResponse(resp *http.Response, advertiseAddr string) (*http.Response, error) {
	if resp == nil || resp.Body == nil {
		return resp, nil
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return resp, err
	}

	rewritten, changed, err := rewriteOpenSearchNodeInfoJSON(data, advertiseAddr)
	if err != nil || !changed {
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
		return resp, err
	}

	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	resp.Header.Del("Content-Encoding")
	resp.TransferEncoding = nil
	return resp, nil
}

func rewriteOpenSearchNodeInfoJSON(data []byte, advertiseAddr string) ([]byte, bool, error) {
	if strings.TrimSpace(advertiseAddr) == "" {
		return data, false, nil
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return data, false, err
	}
	nodes, ok := doc["nodes"].(map[string]any)
	if !ok {
		return data, false, nil
	}

	changed := false
	for _, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			continue
		}
		httpInfo, ok := node["http"].(map[string]any)
		if !ok {
			continue
		}
		if httpInfo["publish_address"] != advertiseAddr {
			httpInfo["publish_address"] = advertiseAddr
			changed = true
		}
	}
	if !changed {
		return data, false, nil
	}

	rewritten, err := json.Marshal(doc)
	if err != nil {
		return data, false, err
	}
	return rewritten, true, nil
}

func (p *OpenSearchProxy) revalidateLoop(ctx context.Context, setupSpanCtx trace.SpanContext, connID string, clientConn, backendConn net.Conn, loginName string, log *slog.Logger) {
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
				backendConn.Close()
				return
			}

			if _, err := p.collectAccess(revalResult); err != nil {
				revalSpan.SetStatus(codes.Error, "permissions revoked")
				revalSpan.End()
				m.RevalFailures.Add(ctx, 1, m.Attrs("waypoint.reval.failures", listenerAttr))
				log.WarnContext(ctx, "permissions revoked, closing connection",
					"user", loginName,
					"error", err,
				)
				clientConn.Close()
				backendConn.Close()
				return
			}

			revalSpan.End()
			log.DebugContext(ctx, "revalidation passed")
		}
	}
}

func (p *OpenSearchProxy) acceptClientTLS(conn net.Conn) (net.Conn, string, error) {
	switch p.ClientTLSMode {
	case "", config.TLSOff:
		return conn, "", nil
	case config.TLSRequire:
		return acceptRequiredMongoTLS(conn, p.ClientTLS)
	case config.TLSOptional:
		if p.ClientTLS == nil {
			return conn, "", nil
		}
		buffered := &bufferedConn{
			Conn:   conn,
			reader: bufio.NewReader(conn),
		}
		isTLS, err := looksLikeTLSClientHello(buffered.reader)
		if err != nil {
			return conn, "", err
		}
		if !isTLS {
			return buffered, "", nil
		}
		return acceptRequiredMongoTLS(buffered, p.ClientTLS)
	default:
		return conn, "", fmt.Errorf("unsupported TLS mode %q", p.ClientTLSMode)
	}
}

func upgradeOpenSearchBackendTLS(conn net.Conn, backend string) (net.Conn, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	if host, _, err := net.SplitHostPort(backend); err == nil {
		tlsConfig.ServerName = host
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	return tlsConn, nil
}

func (p *OpenSearchProxy) effectiveAdvertiseAddr(clientConn net.Conn, sni string) string {
	addr := p.AdvertiseAddr
	if addr == "" && clientConn != nil && clientConn.LocalAddr() != nil {
		addr = clientConn.LocalAddr().String()
	}
	return topologyAddrWithSNI(addr, sni)
}

func (p *OpenSearchProxy) authorize(ctx context.Context, remoteAddr string) (*auth.AuthResult, error) {
	key := remoteHost(remoteAddr) + "\x00" + p.Name
	now := time.Now()

	p.cacheMu.Lock()
	if p.authCache != nil {
		if entry, ok := p.authCache[key]; ok && now.Before(entry.expires) {
			p.cacheMu.Unlock()
			return entry.result, nil
		}
	}
	p.cacheMu.Unlock()

	result, err := p.Auth.Authorize(ctx, remoteAddr, p.Name)
	if err != nil {
		return nil, err
	}

	p.cacheMu.Lock()
	if p.authCache == nil {
		p.authCache = make(map[string]cachedOpenSearchAuth)
	}
	p.authCache[key] = cachedOpenSearchAuth{result: result, expires: now.Add(p.cacheTTL())}
	p.cacheMu.Unlock()
	return result, nil
}

func (p *OpenSearchProxy) getCachedCredential(key string) (cachedOpenSearchCredential, bool) {
	now := time.Now()
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if p.credCache == nil {
		return cachedOpenSearchCredential{}, false
	}
	entry, ok := p.credCache[key]
	if !ok || now.After(entry.expires) {
		return cachedOpenSearchCredential{}, false
	}
	return entry, true
}

func (p *OpenSearchProxy) setCachedCredential(key string, entry cachedOpenSearchCredential) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	if p.credCache == nil {
		p.credCache = make(map[string]cachedOpenSearchCredential)
	}
	p.credCache[key] = entry
}

func (p *OpenSearchProxy) cacheTTL() time.Duration {
	if p.CacheTTL > 0 {
		return p.CacheTTL
	}
	return defaultOpenSearchCacheTTL
}

func remoteHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

type openSearchLimitedConn struct {
	net.Conn
	limits *restrict.ConnLimits
}

func (c *openSearchLimitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if limitErr := c.limits.ReportRead(int64(n)); limitErr != nil {
			return n, limitErr
		}
	}
	return n, err
}

func (c *openSearchLimitedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		if limitErr := c.limits.ReportWrite(int64(n)); limitErr != nil {
			return n, limitErr
		}
	}
	return n, err
}

func openSearchRelayResult(dir restrict.Direction, err error) restrict.RelayResult {
	if err == nil || errors.Is(err, io.EOF) {
		return restrict.RelayResult{Reason: restrict.CloseNormal, InitiatedBy: dir}
	}
	switch {
	case errors.Is(err, restrict.ErrByteLimitExceeded),
		errors.Is(err, restrict.ErrBandwidthLimitExceeded),
		errors.Is(err, restrict.ErrDeadlineExceeded):
		return restrict.RelayResult{Reason: restrict.CloseLimit, InitiatedBy: dir, Err: err}
	default:
		return restrict.RelayResult{Reason: restrict.CloseNetwork, InitiatedBy: dir, Err: err}
	}
}

func writeHTTPError(w io.Writer, status int, message string) {
	if strings.TrimSpace(message) == "" {
		message = http.StatusText(status)
	}
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(message + "\n")),
		ContentLength: int64(len(message) + 1),
		Close:         true,
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("Connection", "close")
	resp.Write(w)
}
