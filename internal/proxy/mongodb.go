package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/logging"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/mongowire"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/restrict"
)

// MongoDBProxy handles MongoDB-aware proxying with Tailscale auth,
// dynamic user provisioning, and mid-session revalidation.
type MongoDBProxy struct {
	Backend       string
	Name          string
	ListenAddr    string // proxy's listen address for topology rewriting
	Auth          Authorizer
	Tracker       *restrict.Tracker
	Provisioner   *provision.MongoProvisioner
	Metrics       *metrics.Metrics
	MongoConfig   *config.MongoDBAdmin
	ClientTLSMode config.TLSMode
	ClientTLS     *tls.Config
	BackendTLS    bool
	TopologyMap   map[string]string
	RevalInterval time.Duration
	Logger        *slog.Logger
	Dialer        func(ctx context.Context, network, addr string) (net.Conn, error)
	BytesRead     *atomic.Int64
	BytesWritten  *atomic.Int64
}

// HandleConn processes a single inbound MongoDB connection.
func (p *MongoDBProxy) HandleConn(ctx context.Context, clientConn net.Conn) {
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
	modeAttr := metrics.AttrMode.String("mongodb")

	ctx, setupSpan := tracer.Start(ctx, "waypoint.connection.setup",
		trace.WithAttributes(
			attribute.String("waypoint.conn_id", connID),
			attribute.String("waypoint.listener", p.Name),
			attribute.String("waypoint.mode", "mongodb"),
			attribute.String("waypoint.backend", p.Backend),
		),
	)
	setupSpanCtx := setupSpan.SpanContext()

	// Step 1: Read client's hello (parse but don't reply yet).
	// We need the backend's real hello to build a proper reply.
	clientHello, err := mongowire.ReadClientHello(clientConn)
	if err != nil {
		recordSetupFailure(ctx, log, m, setupSpan, err, "read client hello failed", "read client hello failed", p.Name, "mongodb")
		return
	}

	log.DebugContext(ctx, "client hello received",
		"is_legacy", clientHello.IsLegacy,
		"has_spec_auth", clientHello.SpecAuth != nil,
	)

	// Step 2: Authorize via Tailscale identity.
	m.AuthAttempts.Add(ctx, 1, m.Attrs("waypoint.auth.attempts", listenerAttr))
	ctx, authSpan := tracer.Start(ctx, "waypoint.auth")
	authStart := time.Now()
	result, err := p.Auth.Authorize(ctx, clientConn.RemoteAddr().String(), p.Name)
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
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "authentication failed: "+err.Error())
		return
	}
	authSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	authSpan.End()

	log.InfoContext(ctx, "authorized",
		"user", result.LoginName,
		"node", result.NodeName,
		"backend", p.Name,
	)

	// Step 3: Acquire connection slot.
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
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "too many connections: "+err.Error())
		return
	}
	slotSpan.End()
	defer release()
	log.DebugContext(ctx, "connection slot acquired")

	// Track connection.
	connStart := time.Now()
	m.ConnTotal.Add(ctx, 1, m.Attrs("waypoint.conn.total", listenerAttr, modeAttr))
	m.ConnActive.Add(ctx, 1, m.Attrs("waypoint.conn.active", listenerAttr, modeAttr))
	defer func() {
		m.ConnActive.Add(ctx, -1, m.Attrs("waypoint.conn.active", listenerAttr, modeAttr))
		m.ConnDuration.Record(ctx, time.Since(connStart).Seconds(),
			m.Attrs("waypoint.conn.duration", listenerAttr, metrics.AttrUser.String(result.LoginName)))
	}()

	// Step 4: Collect all permitted databases and expand into MongoDB roles.
	access := p.collectAccess(result)
	if len(access.Roles) == 0 {
		setupSpan.SetStatus(codes.Error, "no MongoDB permissions")
		setupSpan.End()
		log.WarnContext(ctx, "no MongoDB permissions for any database",
			"user", result.LoginName,
		)
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "not authorized: no database permissions")
		return
	}

	log.DebugContext(ctx, "roles collected",
		"granted_databases", access.GrantedDBs,
		"role_count", len(access.Roles),
	)

	// Step 5: Resolve backend MongoDB credentials.
	mongoUser, mongoPass, backendAuthDB, err := p.resolveBackendCredentials(ctx, result, access)
	if err != nil {
		var missingStatic *missingStaticCredentialError
		if errors.As(err, &missingStatic) {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "static credential missing")
			setupSpan.End()
			log.WarnContext(ctx, "static MongoDB user missing",
				"user", result.LoginName,
				"roles", missingStatic.roles,
			)
			mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, missingStatic.ClientMessage())
			return
		}
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "credential resolution failed")
		setupSpan.End()
		log.ErrorContext(ctx, "credential resolution failed",
			"user", result.LoginName,
			"error", err,
		)
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "internal error")
		return
	}

	// Step 6: Connect to upstream MongoDB.
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
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "backend unavailable")
		return
	}

	if p.BackendTLS {
		upgradedConn, err := upgradeMongoBackendTLS(backendConn, p.Backend)
		if err != nil {
			backendConn.Close()
			dialSpan.RecordError(err)
			dialSpan.SetStatus(codes.Error, "backend TLS failed")
			dialSpan.End()
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "backend TLS failed")
			setupSpan.End()
			log.ErrorContext(ctx, "backend TLS failed", "backend", p.Backend, "error", err)
			mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "backend TLS failed")
			return
		}
		backendConn = upgradedConn
		log.DebugContext(ctx, "backend TLS established")
	}
	dialSpan.End()
	defer backendConn.Close()

	log.DebugContext(ctx, "backend connected")

	// Step 7: Send hello to backend and read its real hello response.
	helloCmd, err := mongowire.BuildHelloCommand(backendAuthDB)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "build hello failed")
		setupSpan.End()
		log.ErrorContext(ctx, "build hello failed", "error", err)
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "internal error")
		return
	}
	if err := mongowire.WriteMessage(backendConn, helloCmd); err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "send hello failed")
		setupSpan.End()
		log.ErrorContext(ctx, "send hello to backend failed", "error", err)
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "backend error")
		return
	}

	backendHelloMsg, err := mongowire.ReadMessage(backendConn)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "read hello reply failed")
		setupSpan.End()
		log.ErrorContext(ctx, "read backend hello failed", "error", err)
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "backend error")
		return
	}

	// Extract the BSON document from the backend's hello response.
	_, backendHelloDoc, err := mongowire.ParseOpMsgBody(backendHelloMsg.Body)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "parse backend hello failed")
		setupSpan.End()
		log.ErrorContext(ctx, "parse backend hello failed", "error", err)
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "backend error")
		return
	}

	// Step 8: Complete client handshake using backend's real hello capabilities.
	proxyAddr := p.ListenAddr
	if proxyAddr == "" {
		proxyAddr = clientConn.LocalAddr().String()
	}
	proxyAddr = topologyAddrWithSNI(proxyAddr, clientSNI)
	topologyMap := topologyMapWithSNI(p.TopologyMap, clientSNI)

	hsResult, err := mongowire.CompleteHandshakeWithTopologyMap(clientConn, clientHello, backendHelloDoc, proxyAddr, topologyMap)
	if err != nil {
		if errors.Is(err, mongowire.ErrAuthFailed) {
			// Client presented wrong credentials. It already received a proper
			// SCRAM rejection; this is a client error, not a proxy fault, so it
			// is not an error span — count it as an auth failure instead.
			setupSpan.SetAttributes(attribute.String("waypoint.setup_outcome", "auth_failed"))
			setupSpan.End()
			m.AuthFailures.Add(ctx, 1, m.Attrs("waypoint.auth.failures", listenerAttr))
			m.ConnRejected.Add(ctx, 1, m.Attrs("waypoint.conn.rejected", listenerAttr, modeAttr))
			log.WarnContext(ctx, "client handshake auth failed", "error", err)
			return
		}
		recordSetupFailure(ctx, log, m, setupSpan, err, "client handshake failed", "client handshake failed", p.Name, "mongodb")
		return
	}

	log.DebugContext(ctx, "client handshake complete",
		"auth_db", hsResult.AuthDB,
		"username", hsResult.Username,
		"has_first_command", hsResult.FirstCommand != nil,
	)

	// Step 9: Authenticate with backend using provisioned credentials.
	if err := mongowire.AuthenticateBackend(backendConn, mongoUser, mongoPass, backendAuthDB); err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "backend auth failed")
		setupSpan.End()
		log.ErrorContext(ctx, "backend auth failed", "user", mongoUser, "error", err)
		sendMongoError(clientConn, 0, "backend authentication failed")
		return
	}

	log.DebugContext(ctx, "backend auth complete")

	// Step 9b: Forward buffered first command if client connected without auth.
	if hsResult.FirstCommand != nil {
		if err := mongowire.WriteMessage(backendConn, hsResult.FirstCommand); err != nil {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "forward first command failed")
			setupSpan.End()
			log.ErrorContext(ctx, "forward first command failed", "error", err)
			return
		}
		// Read the response and send it back to the client.
		// Apply topology rewriting since this response may be a hello/isMaster
		// that contains RS member addresses.
		resp, err := mongowire.ReadMessage(backendConn)
		if err != nil {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "read first response failed")
			setupSpan.End()
			log.ErrorContext(ctx, "read first response failed", "error", err)
			return
		}
		if resp.Header.OpCode == mongowire.OpMsg {
			resp.Body = mongowire.RewriteTopologyWithMap(resp.Body, proxyAddr, topologyMap)
			// Update message length if body size changed.
			resp.Header.MessageLength = int32(mongowire.HeaderSize + len(resp.Body))
		}
		if err := mongowire.WriteMessage(clientConn, resp); err != nil {
			setupSpan.RecordError(err)
			setupSpan.SetStatus(codes.Error, "send first response failed")
			setupSpan.End()
			log.ErrorContext(ctx, "send first response failed", "error", err)
			return
		}
	}

	// Setup complete.
	setupSpan.SetAttributes(attribute.String("waypoint.user", result.LoginName))
	setupSpan.End()

	// Step 10: Wrap backend with topology rewriter so replica set member
	// addresses in hello/isMaster responses point to the proxy.
	rewrittenBackend := mongowire.NewTopologyRewriterWithMap(backendConn, proxyAddr, topologyMap)

	// Step 11: Bidirectional relay with limits.
	cl := p.Tracker.WrapConn(ctx, result.LoginName, result.Limits, p.Name)

	// Step 12: Mid-session revalidation.
	revalCtx, revalCancel := context.WithCancel(ctx)
	defer revalCancel()
	if p.RevalInterval > 0 {
		go p.revalidateLoop(revalCtx, setupSpanCtx, connID, clientConn, backendConn, result.LoginName, log)
	}

	log.DebugContext(ctx, "relay started")

	relayResult := restrict.Relay(clientConn, rewrittenBackend, cl)

	switch relayResult.Reason {
	case restrict.CloseLimit:
		log.WarnContext(ctx, "relay ended: limit exceeded",
			"user", result.LoginName,
			"close_reason", relayResult.Reason,
			"initiated_by", relayResult.InitiatedBy,
			"error", relayResult.Err,
		)
	case restrict.CloseNetwork:
		log.WarnContext(ctx, "relay ended: network error",
			"user", result.LoginName,
			"initiated_by", relayResult.InitiatedBy,
			"error", relayResult.Err,
		)
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
			attribute.String("waypoint.close_reason", string(relayResult.Reason)),
			attribute.String("waypoint.close_initiated_by", string(relayResult.InitiatedBy)),
		),
	)
	closeSpan.End()

	log.InfoContext(ctx, "connection closed",
		"duration", time.Since(connStart),
		"bytes_read", br,
		"bytes_written", bw,
		"close_reason", relayResult.Reason,
		"initiated_by", relayResult.InitiatedBy,
	)
}

type mongoAccess struct {
	Roles      []provision.MongoRole
	GrantedDBs []string
	Grants     []mongoDatabaseGrant
}

type mongoDatabaseGrant struct {
	Database    string
	Permissions []string
}

type mongoStaticCredential struct {
	Name         string
	Username     string
	Password     string
	AuthDatabase string
}

type missingStaticCredentialError struct {
	roles string
}

func (e *missingStaticCredentialError) Error() string {
	return "no static MongoDB user matches roles " + e.roles
}

func (e *missingStaticCredentialError) ClientMessage() string {
	return "not authorized: no static MongoDB user configured for requested permissions"
}

func (p *MongoDBProxy) resolveBackendCredentials(ctx context.Context, result *auth.AuthResult, access mongoAccess) (string, string, string, error) {
	authDB := p.MongoConfig.EffectiveAuthDatabase()
	switch p.MongoConfig.EffectiveProvisionMode() {
	case config.MongoProvisionStatic:
		cred, err := p.selectStaticCredential(access)
		if err != nil {
			return "", "", "", err
		}
		if cred.AuthDatabase != "" {
			authDB = cred.AuthDatabase
		}
		p.Logger.DebugContext(ctx, "static MongoDB user selected",
			"static_user", cred.Name,
			"mongo_user", cred.Username,
			"auth_database", authDB,
		)
		return cred.Username, cred.Password, authDB, nil
	case config.MongoProvisionDatabase:
		if p.Provisioner == nil {
			return "", "", "", fmt.Errorf("mongodb provisioner is not configured")
		}
		m := p.Metrics
		listenerAttr := metrics.AttrListener.String(p.Name)
		tracer := m.Tracer()

		provStart := time.Now()
		m.ProvisionTotal.Add(ctx, 1, m.Attrs("waypoint.provision.total", listenerAttr))
		ctx, provSpan := tracer.Start(ctx, "waypoint.provision")
		mongoUser, mongoPass, err := p.Provisioner.EnsureUser(ctx, result.LoginName, result.NodeName, access.Roles)
		provSpan.End()
		m.ProvisionLatency.Record(ctx, time.Since(provStart).Seconds(),
			m.Attrs("waypoint.provision.latency", listenerAttr))
		if err != nil {
			m.ProvisionErrors.Add(ctx, 1, m.Attrs("waypoint.provision.errors", listenerAttr))
			return "", "", "", fmt.Errorf("provision user: %w", err)
		}
		p.Logger.DebugContext(ctx, "user provisioned", "mongo_user", mongoUser)
		return mongoUser, mongoPass, authDB, nil
	default:
		return "", "", "", fmt.Errorf("unsupported mongodb provision mode %q", p.MongoConfig.EffectiveProvisionMode())
	}
}

// collectAccess gathers all MongoDB roles from matched ACL rules across all
// concrete permitted databases. Wildcard grants are not expanded because the
// provisioner needs concrete MongoDB role assignments.
func (p *MongoDBProxy) collectAccess(result *auth.AuthResult) mongoAccess {
	permsByDB := make(map[string][]string)

	for _, r := range result.MatchedRules {
		bc, ok := r.Backends[p.Name]
		if !ok || bc.Mongo == nil {
			continue
		}
		for dbName, dbPerms := range bc.Mongo.Databases {
			if dbName == "*" {
				continue
			}
			permsByDB[dbName] = append(permsByDB[dbName], dbPerms.Permissions...)
		}
	}

	grantedDBs := make([]string, 0, len(permsByDB))
	for dbName := range permsByDB {
		grantedDBs = append(grantedDBs, dbName)
	}
	sort.Strings(grantedDBs)

	var access mongoAccess
	access.GrantedDBs = grantedDBs
	seenRoles := make(map[string]bool)
	for _, dbName := range grantedDBs {
		perms := normalizeMongoPermissions(permsByDB[dbName])
		roles, err := provision.ExpandMongoPresets(perms, dbName)
		if err != nil {
			p.Logger.Warn("invalid permissions", "database", dbName, "error", err)
			continue
		}
		access.Grants = append(access.Grants, mongoDatabaseGrant{
			Database:    dbName,
			Permissions: perms,
		})
		for _, role := range roles {
			key := mongoRoleKey(role)
			if seenRoles[key] {
				continue
			}
			seenRoles[key] = true
			access.Roles = append(access.Roles, role)
		}
	}

	return access
}

func (p *MongoDBProxy) selectStaticCredential(access mongoAccess) (mongoStaticCredential, error) {
	if p.MongoConfig == nil || p.MongoConfig.Provision == nil {
		return mongoStaticCredential{}, fmt.Errorf("mongodb static provisioning is not configured")
	}
	wantRoles := mongoRoleSignature(access.Roles)

	for _, user := range p.MongoConfig.Provision.StaticUsers {
		if staticUserMatchesPermissions(user, access.Grants) {
			return p.staticCredential(user), nil
		}

		roles, ok, err := staticUserRoles(user)
		if err != nil {
			return mongoStaticCredential{}, fmt.Errorf("static user %q roles: %w", staticUserName(user), err)
		}
		if !ok {
			continue
		}
		if mongoRoleSignature(roles) == wantRoles {
			return p.staticCredential(user), nil
		}
	}

	return mongoStaticCredential{}, &missingStaticCredentialError{roles: wantRoles}
}

func (p *MongoDBProxy) staticCredential(user config.MongoStaticUser) mongoStaticCredential {
	authDB := strings.TrimSpace(user.AuthDatabase)
	if authDB == "" {
		authDB = p.MongoConfig.EffectiveAuthDatabase()
	}
	return mongoStaticCredential{
		Name:         staticUserName(user),
		Username:     user.Username,
		Password:     user.Password,
		AuthDatabase: authDB,
	}
}

func staticUserName(user config.MongoStaticUser) string {
	if strings.TrimSpace(user.Name) != "" {
		return user.Name
	}
	return user.Username
}

func staticUserMatchesPermissions(user config.MongoStaticUser, grants []mongoDatabaseGrant) bool {
	if len(user.Roles) > 0 || strings.TrimSpace(user.Database) != "" || len(user.Permissions) == 0 || len(grants) == 0 {
		return false
	}
	want := mongoPermissionSignature(user.Permissions)
	if want == "" {
		return false
	}
	for _, grant := range grants {
		if mongoPermissionSignature(grant.Permissions) != want {
			return false
		}
	}
	return true
}

func staticUserRoles(user config.MongoStaticUser) ([]provision.MongoRole, bool, error) {
	if len(user.Roles) > 0 {
		roles := make([]provision.MongoRole, 0, len(user.Roles))
		for _, role := range user.Roles {
			roles = append(roles, provision.MongoRole{Role: strings.TrimSpace(role.Role), DB: strings.TrimSpace(role.DB)})
		}
		return roles, true, nil
	}
	if strings.TrimSpace(user.Database) == "" {
		return nil, false, nil
	}
	roles, err := provision.ExpandMongoPresets(user.Permissions, strings.TrimSpace(user.Database))
	return roles, true, err
}

func normalizeMongoPermissions(perms []string) []string {
	seen := make(map[string]bool)
	for _, perm := range perms {
		perm = strings.ToLower(strings.TrimSpace(perm))
		if perm == "" || seen[perm] {
			continue
		}
		seen[perm] = true
	}

	if seen["admin"] {
		delete(seen, "readwrite")
		delete(seen, "readonly")
	} else if seen["readwrite"] {
		delete(seen, "readonly")
	}

	normalized := make([]string, 0, len(seen))
	for perm := range seen {
		normalized = append(normalized, perm)
	}
	sort.Strings(normalized)
	return normalized
}

func mongoPermissionSignature(perms []string) string {
	return strings.Join(normalizeMongoPermissions(perms), ",")
}

func mongoRoleSignature(roles []provision.MongoRole) string {
	keys := make([]string, 0, len(roles))
	seen := make(map[string]bool)
	for _, role := range roles {
		key := mongoRoleKey(role)
		if seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func mongoRoleKey(role provision.MongoRole) string {
	return strings.TrimSpace(role.DB) + "." + strings.TrimSpace(role.Role)
}

func (p *MongoDBProxy) acceptClientTLS(conn net.Conn) (net.Conn, string, error) {
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

func acceptRequiredMongoTLS(conn net.Conn, tlsConfig *tls.Config) (net.Conn, string, error) {
	if tlsConfig == nil {
		return conn, "", fmt.Errorf("TLS config is required")
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return conn, "", fmt.Errorf("TLS handshake: %w", err)
	}
	return tlsConn, tlsConn.ConnectionState().ServerName, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func looksLikeTLSClientHello(reader *bufio.Reader) (bool, error) {
	header, err := reader.Peek(5)
	if err != nil {
		return false, err
	}

	recordLength := int(header[3])<<8 | int(header[4])
	return header[0] == 0x16 &&
		header[1] == 0x03 &&
		header[2] >= 0x01 &&
		header[2] <= 0x04 &&
		recordLength > 0, nil
}

func upgradeMongoBackendTLS(conn net.Conn, backend string) (net.Conn, error) {
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

func topologyMapWithSNI(topologyMap map[string]string, sni string) map[string]string {
	if sni == "" || len(topologyMap) == 0 {
		return topologyMap
	}
	rewritten := make(map[string]string, len(topologyMap))
	for backend, advertise := range topologyMap {
		rewritten[backend] = topologyAddrWithSNI(advertise, sni)
	}
	return rewritten
}

func topologyAddrWithSNI(addr, sni string) string {
	if sni == "" {
		return addr
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return sni
	}
	return net.JoinHostPort(sni, port)
}

// revalidateLoop periodically re-checks WhoIs + caps. Closes connections
// if the user's grant is revoked.
func (p *MongoDBProxy) revalidateLoop(ctx context.Context, setupSpanCtx trace.SpanContext, connID string, clientConn, backendConn net.Conn, loginName string, log *slog.Logger) {
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

			// Check that at least one MongoDB permission still exists.
			access := p.collectAccess(revalResult)
			if len(access.Roles) == 0 {
				revalSpan.SetStatus(codes.Error, "permissions revoked")
				revalSpan.End()
				m.RevalFailures.Add(ctx, 1, m.Attrs("waypoint.reval.failures", listenerAttr))
				log.WarnContext(ctx, "permissions revoked, closing connection",
					"user", loginName,
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

// sendMongoError sends a MongoDB error response on the connection.
func sendMongoError(conn net.Conn, responseTo int32, message string) {
	reply, err := mongowire.BuildErrorReply(responseTo, 18, message)
	if err != nil {
		return
	}
	mongowire.WriteMessage(conn, reply)
}
