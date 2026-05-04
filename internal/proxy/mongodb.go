package proxy

import (
	"context"
	"log/slog"
	"net"
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
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "read client hello failed")
		setupSpan.End()
		log.ErrorContext(ctx, "read client hello failed", "error", err)
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
	roles, grantedDBs := p.collectRoles(result)
	if len(roles) == 0 {
		setupSpan.SetStatus(codes.Error, "no MongoDB permissions")
		setupSpan.End()
		log.WarnContext(ctx, "no MongoDB permissions for any database",
			"user", result.LoginName,
		)
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "not authorized: no database permissions")
		return
	}

	log.DebugContext(ctx, "roles collected",
		"granted_databases", grantedDBs,
		"role_count", len(roles),
	)

	// Step 5: Provision dynamic MongoDB user with all permitted roles.
	provStart := time.Now()
	m.ProvisionTotal.Add(ctx, 1, m.Attrs("waypoint.provision.total", listenerAttr))
	ctx, provSpan := tracer.Start(ctx, "waypoint.provision")
	mongoUser, mongoPass, err := p.Provisioner.EnsureUser(ctx, result.LoginName, result.NodeName, roles)
	provSpan.End()
	m.ProvisionLatency.Record(ctx, time.Since(provStart).Seconds(),
		m.Attrs("waypoint.provision.latency", listenerAttr))
	if err != nil {
		m.ProvisionErrors.Add(ctx, 1, m.Attrs("waypoint.provision.errors", listenerAttr))
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "provision failed")
		setupSpan.End()
		log.ErrorContext(ctx, "provision failed",
			"user", result.LoginName,
			"error", err,
		)
		mongowire.SendErrorAsHelloReply(clientConn, clientHello, 18, "internal error")
		return
	}

	log.DebugContext(ctx, "user provisioned", "mongo_user", mongoUser)

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
	dialSpan.End()
	defer backendConn.Close()

	log.DebugContext(ctx, "backend connected")

	// Step 7: Send hello to backend and read its real hello response.
	helloCmd, err := mongowire.BuildHelloCommand(p.MongoConfig.AuthDatabase)
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

	hsResult, err := mongowire.CompleteHandshake(clientConn, clientHello, backendHelloDoc, proxyAddr)
	if err != nil {
		setupSpan.RecordError(err)
		setupSpan.SetStatus(codes.Error, "client handshake failed")
		setupSpan.End()
		log.ErrorContext(ctx, "client handshake failed", "error", err)
		return
	}

	log.DebugContext(ctx, "client handshake complete",
		"auth_db", hsResult.AuthDB,
		"username", hsResult.Username,
		"has_first_command", hsResult.FirstCommand != nil,
	)

	// Step 9: Authenticate with backend using provisioned credentials.
	if err := mongowire.AuthenticateBackend(backendConn, mongoUser, mongoPass, p.MongoConfig.AuthDatabase); err != nil {
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
			resp.Body = mongowire.RewriteTopology(resp.Body, proxyAddr)
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
	rewrittenBackend := mongowire.NewTopologyRewriter(backendConn, proxyAddr)

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

// collectRoles gathers all MongoDB roles from matched ACL rules across all
// permitted databases. Returns the expanded roles and the list of granted
// database names (for logging).
func (p *MongoDBProxy) collectRoles(result *auth.AuthResult) ([]provision.MongoRole, []string) {
	var allRoles []provision.MongoRole
	var grantedDBs []string
	seen := make(map[string]bool)

	for _, r := range result.MatchedRules {
		bc, ok := r.Backends[p.Name]
		if !ok || bc.Mongo == nil {
			continue
		}
		for dbName, dbPerms := range bc.Mongo.Databases {
			if dbName == "*" {
				continue // wildcards don't expand to concrete roles here
			}
			if !seen[dbName] {
				seen[dbName] = true
				grantedDBs = append(grantedDBs, dbName)
			}
			roles, err := provision.ExpandMongoPresets(dbPerms.Permissions, dbName)
			if err != nil {
				p.Logger.Warn("invalid permissions", "database", dbName, "error", err)
				continue
			}
			allRoles = append(allRoles, roles...)
		}
	}

	return allRoles, grantedDBs
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
			roles, _ := p.collectRoles(revalResult)
			if len(roles) == 0 {
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
