// Package web serves the browser-facing SQL console.
//
// The console is stateless. There is no login, no session cookie, and no
// server-side session store: every request is authorized on its own by asking
// Tailscale who the caller is and re-reading their capability grants. A
// revoked grant therefore takes effect on the very next request, which is
// finer-grained than the timer-based revalidation a long-lived wire connection
// has to use.
//
// Nothing the user does is preserved. Closing the browser discards the tabs,
// the buffers, and the results; the server keeps only pools and catalog
// caches, both of which are reconstructible and hold no session state.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/querylog"
	"github.com/redoapp/waypoint/internal/restrict"
	"tailscale.com/client/local"
)

// Server is one web console listener.
type Server struct {
	name      string
	backend   string
	databases []string

	lc      *local.Client
	tracker *restrict.Tracker
	pools   *poolManager
	catalog *catalogCache

	// typeNames memoizes user-defined type OIDs → names, which pgx's built-in
	// type map does not carry. Keyed by database, since OIDs are per-database.
	typeNames sync.Map

	webCfg      *config.WebConfig
	queryLog    *querylog.Emitter
	queryLogCfg *config.QueryLogConfig
	metrics     *metrics.Metrics
	logger      *slog.Logger

	mux *http.ServeMux
}

// Options configures a console listener.
type Options struct {
	Name        string
	Backend     string
	LC          *local.Client
	Tracker     *restrict.Tracker
	Provisioner *provision.Provisioner
	PGConfig    *config.PostgresAdmin
	WebConfig   *config.WebConfig
	QueryLog    *querylog.Emitter
	QueryLogCfg *config.QueryLogConfig
	Metrics     *metrics.Metrics
	Logger      *slog.Logger
	BackendTLS  bool
	PeerService string
	DialFunc    func(ctx context.Context, network, addr string) (net.Conn, error)
	LookupFunc  func(ctx context.Context, host string) ([]string, error)
}

// New builds a console server. Call Run to start its background pool reaper.
func New(o Options) *Server {
	adminDB := ""
	if o.PGConfig != nil {
		adminDB = o.PGConfig.AdminDatabase
	}
	s := &Server{
		name:      o.Name,
		backend:   o.Backend,
		databases: o.WebConfig.EffectiveDatabases(adminDB),
		lc:        o.LC,
		tracker:   o.Tracker,
		catalog:   newCatalogCache(time.Minute),
		webCfg:    o.WebConfig,
		queryLog:  o.QueryLog,
		metrics:   o.Metrics,
		logger:    o.Logger,
	}
	s.queryLogCfg = o.QueryLogCfg
	if s.queryLogCfg == nil {
		s.queryLogCfg = &config.QueryLogConfig{}
	}
	s.pools = newPoolManager(
		o.Provisioner,
		o.Backend,
		o.BackendTLS,
		o.PeerService,
		o.DialFunc,
		o.LookupFunc,
		o.WebConfig.EffectiveStatementTimeout(),
		o.WebConfig.EffectiveMaxPoolConns(),
		o.WebConfig.EffectiveIdlePoolTimeout(),
		o.Logger,
	)
	s.routes()
	return s
}

// Run drives background maintenance until ctx is cancelled.
func (s *Server) Run(ctx context.Context) { s.pools.run(ctx) }

// Handler returns the console's HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	m := http.NewServeMux()
	m.Handle("GET /", assetHandler())
	m.HandleFunc("GET /api/v1/session", s.handleSession)
	m.HandleFunc("GET /api/v1/schema", s.handleSchema)
	m.HandleFunc("POST /api/v1/columns", s.handleColumns)
	m.HandleFunc("POST /api/v1/complete", s.handleComplete)
	m.HandleFunc("POST /api/v1/diagnostics", s.handleDiagnostics)
	m.HandleFunc("POST /api/v1/query", s.handleQuery)
	m.HandleFunc("POST /api/v1/cancel", s.handleCancel)
	s.mux = m
}

// session is the per-request identity, rebuilt from scratch every time.
type session struct {
	Auth  *auth.AuthResult
	ReqID string
}

// authorize resolves the caller's Tailscale identity and capability grants.
//
// This runs on every request. There is no cached authorization decision:
// caching one would trade away the property that makes this design safe, which
// is that a revoked grant stops working immediately.
func (s *Server) authorize(r *http.Request) (*session, error) {
	result, err := auth.Authorize(r.Context(), s.lc, r.RemoteAddr, s.name, s.logger)
	if err != nil {
		return nil, err
	}
	return &session{Auth: result, ReqID: uuid.NewString()}, nil
}

// guard applies the checks that identity-by-source-IP makes necessary.
//
// Because the browser is authenticated by where it sits on the tailnet rather
// than by a credential it holds, a page on any other origin could otherwise
// make the browser issue authenticated requests here. There is no cookie to
// mark SameSite, so the origin checks below are the defence, and they run
// before anything else touches the database.
func (s *Server) guard(w http.ResponseWriter, r *http.Request) bool {
	// Reject cross-site requests outright. Fetch metadata is sent by every
	// browser that can reach this console.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		switch site {
		case "same-origin", "none":
		default:
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return false
		}
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// Fall back to Origin for clients that omit fetch metadata.
		if origin := r.Header.Get("Origin"); origin != "" {
			if !sameOrigin(origin, r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return false
			}
		} else if r.Header.Get("Sec-Fetch-Site") == "" {
			// No Origin and no fetch metadata: not a browser we can vouch
			// for. The console's own JS always sends one of them.
			http.Error(w, "missing origin", http.StatusForbidden)
			return false
		}
	}
	return true
}

func sameOrigin(origin string, r *http.Request) bool {
	host := r.Host
	trimmed := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return strings.EqualFold(trimmed, host)
}

func (s *Server) fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// resolveDatabase picks the target database and checks the caller's grant
// covers it.
func (s *Server) resolveDatabase(sess *session, requested string) (string, *auth.DBPermissions, error) {
	db := strings.TrimSpace(requested)
	if db == "" {
		db = s.databases[0]
	}
	allowed := false
	for _, d := range s.databases {
		if d == db {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", nil, fmt.Errorf("database %q is not offered by this listener", db)
	}
	perms := auth.DatabasePermissions(sess.Auth, s.name, db)
	if perms == nil {
		return "", nil, fmt.Errorf("your capability grant does not include database %q", db)
	}
	return db, perms, nil
}

// withPool resolves identity, database, and a pooled connection, retrying once
// if the pooled credential has gone stale because another instance rotated the
// role's password.
func (s *Server) withPool(w http.ResponseWriter, r *http.Request, database string,
	fn func(ctx context.Context, sess *session, pool *pgxpool.Pool, pgUser, db, cacheKey string) error) {

	if !s.guard(w, r) {
		return
	}
	sess, err := s.authorize(r)
	if err != nil {
		s.logger.InfoContext(r.Context(), "console access denied", "remote", r.RemoteAddr, "error", err)
		s.fail(w, http.StatusForbidden, err.Error())
		return
	}
	db, perms, err := s.resolveDatabase(sess, database)
	if err != nil {
		s.fail(w, http.StatusForbidden, err.Error())
		return
	}

	ctx := r.Context()
	pool, pgUser, err := s.pools.acquire(ctx, sess.Auth.LoginName, sess.Auth.NodeName, db, perms)
	if err != nil {
		s.fail(w, http.StatusBadGateway, err.Error())
		return
	}

	cacheKey := pgUser + "\x00" + db
	if err := fn(ctx, sess, pool, pgUser, db, cacheKey); err != nil {
		if isAuthFailure(err) {
			s.pools.invalidate(sess.Auth.LoginName, sess.Auth.NodeName, db)
			s.catalog.Invalidate(cacheKey)
			pool, pgUser, err = s.pools.acquire(ctx, sess.Auth.LoginName, sess.Auth.NodeName, db, perms)
			if err == nil {
				cacheKey = pgUser + "\x00" + db
				err = fn(ctx, sess, pool, pgUser, db, cacheKey)
			}
		}
		if err != nil {
			s.logger.WarnContext(ctx, "console request failed",
				"user", sess.Auth.LoginName, "database", db, "error", err)
			s.fail(w, http.StatusBadGateway, err.Error())
		}
	}
}

// --- handlers ---

type sessionResponse struct {
	User      string   `json:"user"`
	Node      string   `json:"node"`
	Listener  string   `json:"listener"`
	Backend   string   `json:"backend"`
	Databases []string `json:"databases"`
	Database  string   `json:"database"`
	Presets   []string `json:"presets"`
	MaxRows   int      `json:"maxRows"`
	Timeout   string   `json:"statementTimeout"`
	MaxConns  int      `json:"maxConns"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if !s.guard(w, r) {
		return
	}
	sess, err := s.authorize(r)
	if err != nil {
		s.fail(w, http.StatusForbidden, err.Error())
		return
	}
	db := s.databases[0]
	var presets []string
	if perms := auth.DatabasePermissions(sess.Auth, s.name, db); perms != nil {
		presets = perms.Permissions
	}
	writeJSON(w, sessionResponse{
		User:      sess.Auth.LoginName,
		Node:      sess.Auth.NodeName,
		Listener:  s.name,
		Backend:   s.backend,
		Databases: s.databases,
		Database:  db,
		Presets:   presets,
		MaxRows:   s.webCfg.EffectiveMaxRows(),
		Timeout:   s.webCfg.EffectiveStatementTimeout().String(),
		MaxConns:  sess.Auth.Limits.MaxConns,
	})
}

func (s *Server) handleSchema(w http.ResponseWriter, r *http.Request) {
	database := r.URL.Query().Get("database")
	s.withPool(w, r, database, func(ctx context.Context, sess *session, pool *pgxpool.Pool, pgUser, db, cacheKey string) error {
		if r.URL.Query().Get("refresh") == "1" {
			s.catalog.Invalidate(cacheKey)
		}
		cat, err := s.catalog.Get(ctx, cacheKey, pool)
		if err != nil {
			return err
		}
		writeJSON(w, cat)
		return nil
	})
}

type columnsRequest struct {
	Database string `json:"database"`
	Schema   string `json:"schema"`
	Table    string `json:"table"`
}

func (s *Server) handleColumns(w http.ResponseWriter, r *http.Request) {
	var req columnsRequest
	if err := decodeBody(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.withPool(w, r, req.Database, func(ctx context.Context, sess *session, pool *pgxpool.Pool, pgUser, db, cacheKey string) error {
		// Only relations the catalog already exposes are readable here, so a
		// crafted request cannot introspect something the grant excludes.
		cat, err := s.catalog.Get(ctx, cacheKey, pool)
		if err != nil {
			return err
		}
		t, ok := cat.lookup(req.Schema, req.Table)
		if !ok {
			s.fail(w, http.StatusNotFound, "unknown relation")
			return nil
		}
		cols, err := s.catalog.Columns(ctx, cacheKey, pool, t.Schema, t.Name)
		if err != nil {
			return err
		}
		writeJSON(w, map[string]any{"schema": t.Schema, "table": t.Name, "columns": cols})
		return nil
	})
}

type completeRequest struct {
	Database  string `json:"database"`
	SQL       string `json:"sql"`
	CursorPos int    `json:"cursorPos"`
}

func (s *Server) handleComplete(w http.ResponseWriter, r *http.Request) {
	var req completeRequest
	if err := decodeBody(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.withPool(w, r, req.Database, func(ctx context.Context, sess *session, pool *pgxpool.Pool, pgUser, db, cacheKey string) error {
		res, err := s.complete(ctx, pool, cacheKey, req.SQL, req.CursorPos)
		if err != nil {
			return err
		}
		writeJSON(w, res)
		return nil
	})
}

type diagnosticsRequest struct {
	Database string `json:"database"`
	SQL      string `json:"sql"`
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	var req diagnosticsRequest
	if err := decodeBody(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.withPool(w, r, req.Database, func(ctx context.Context, sess *session, pool *pgxpool.Pool, pgUser, db, cacheKey string) error {
		writeJSON(w, map[string]any{"diagnostics": s.diagnose(ctx, pool, cacheKey, req.SQL)})
		return nil
	})
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	var req queryRequest
	if err := decodeBody(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.SQL) == "" {
		s.fail(w, http.StatusBadRequest, "empty statement")
		return
	}

	s.withPool(w, r, req.Database, func(ctx context.Context, sess *session, pool *pgxpool.Pool, pgUser, db, cacheKey string) error {
		// A web query consumes the same connection budget as a wire
		// connection, so the console cannot be used to sidestep limits.
		release, err := s.tracker.Acquire(ctx, sess.Auth.LoginName, sess.Auth.Limits, s.name)
		if err != nil {
			s.fail(w, http.StatusTooManyRequests, err.Error())
			return nil
		}
		defer release()

		stmt := req.SQL
		if !req.RunAll {
			if span, ok := statementAt(req.SQL, req.CursorPos); ok {
				stmt = span.Text
			}
		}
		stmt = strings.TrimSuffix(strings.TrimSpace(stmt), ";")
		if stmt == "" {
			s.fail(w, http.StatusBadRequest, "no statement at cursor")
			return nil
		}

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		out := newNDJSON(w)
		return s.execute(ctx, out, pool, sess, db, stmt)
	})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	var req cancelRequest
	if err := decodeBody(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, err.Error())
		return
	}
	s.withPool(w, r, req.Database, func(ctx context.Context, sess *session, pool *pgxpool.Pool, pgUser, db, cacheKey string) error {
		if err := s.cancel(ctx, pool, pgUser, req.PID); err != nil {
			s.fail(w, http.StatusConflict, err.Error())
			return nil
		}
		s.logger.InfoContext(ctx, "console query cancelled",
			"user", sess.Auth.LoginName, "pid", req.PID, "database", db)
		writeJSON(w, map[string]bool{"cancelled": true})
		return nil
	})
}

const maxBodyBytes = 1 << 20

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid request body")
	}
	return nil
}

// resolveQueryLogLevel mirrors the proxy's resolution: the ACL grant chooses a
// level, the listener's ceiling clamps it.
func resolveQueryLogLevel(cfg *config.QueryLogConfig, aclLevel *querylog.Level) querylog.Level {
	if cfg == nil {
		return querylog.LevelOff
	}
	fallback, err := querylog.ParseLevel(cfg.EffectiveLevel())
	if err != nil {
		return querylog.LevelOff
	}
	ceiling, err := querylog.ParseLevel(cfg.EffectiveMaxLevel())
	if err != nil {
		return querylog.LevelOff
	}
	want := fallback
	if aclLevel != nil {
		want = *aclLevel
	}
	return querylog.Clamp(want, ceiling)
}
