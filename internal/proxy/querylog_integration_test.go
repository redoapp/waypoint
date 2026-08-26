//go:build integration

package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/proxy"
	"github.com/redoapp/waypoint/internal/querylog"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// queryLogCapture collects the records an Emitter writes.
type queryLogCapture struct {
	emitter *querylog.Emitter

	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *queryLogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// records drains the emitter and returns the query records it produced.
func (c *queryLogCapture) records(t *testing.T) []map[string]any {
	t.Helper()
	c.emitter.Close()

	c.mu.Lock()
	defer c.mu.Unlock()

	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(c.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decoding %q: %v", line, err)
		}
		if rec["msg"] == "query" {
			out = append(out, rec)
		}
	}
	return out
}

// find returns the first record whose statement or table list mentions needle.
func (c *queryLogCapture) find(t *testing.T, needle string) map[string]any {
	t.Helper()
	for _, rec := range c.records(t) {
		if stmt, _ := rec["statement"].(string); strings.Contains(stmt, needle) {
			return rec
		}
		if tables, ok := rec["tables"].([]any); ok {
			for _, tbl := range tables {
				if s, _ := tbl.(string); strings.Contains(s, needle) {
					return rec
				}
			}
		}
	}
	return nil
}

// withQueryLog returns a proxy option enabling query logging at the given
// listener level and ceiling, capturing the records it produces.
func withQueryLog(t *testing.T, level, maxLevel string) (func(*proxy.PostgresProxy), *queryLogCapture) {
	t.Helper()

	cap := &queryLogCapture{}
	cap.emitter = querylog.NewEmitter(
		slog.New(slog.NewJSONHandler(cap, &slog.HandlerOptions{Level: slog.LevelDebug})),
		1024,
		querylog.Counters{},
	)
	t.Cleanup(cap.emitter.Close)

	return func(p *proxy.PostgresProxy) {
		p.QueryLog = cap.emitter
		p.QueryLogConfig = &config.QueryLogConfig{Level: level, MaxLevel: maxLevel}
	}, cap
}

func queryLogAuthResult(loggingCap *auth.LoggingCap) *auth.AuthResult {
	result := makeAuthResult("waypoint_test", auth.DBPermissions{
		Permissions: []string{"readonly"},
	}, nil)
	if loggingCap != nil {
		bc := result.MatchedRules[0].Backends["test-listener"]
		bc.Logging = loggingCap
		result.MatchedRules[0].Backends["test-listener"] = bc

		lvl, err := querylog.ParseLevel(loggingCap.Queries)
		if err == nil {
			result.QueryLog = &lvl
		}
	}
	return result
}

// At metadata level the record describes the statement — verb, kind, tables,
// fingerprint — without carrying any of its text.
func TestIntegration_Proxy_QueryLogMetadata(t *testing.T) {
	aconn := adminConn(t)
	ctx := context.Background()
	if _, err := aconn.Exec(ctx, "CREATE TABLE IF NOT EXISTS public.qlog_orders (id int)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		c := adminConn(t)
		c.Exec(context.Background(), "DROP TABLE IF EXISTS public.qlog_orders")
	})

	opt, cap := withQueryLog(t, config.QueryLogMetadata, config.QueryLogMetadata)
	addr := setupProxyWithAuth(t, &mockAuthorizer{result: queryLogAuthResult(nil)}, opt)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	conn := proxyConnect(t, addr, "waypoint_test")
	var n int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM public.qlog_orders WHERE id = 42").Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	conn.Close(ctx)

	rec := cap.find(t, "qlog_orders")
	if rec == nil {
		t.Fatalf("no query log record mentions qlog_orders; got %v", cap.records(t))
	}

	if rec["op"] != "SELECT" {
		t.Errorf("op = %v, want SELECT", rec["op"])
	}
	if rec["kind"] != querylog.KindRead {
		t.Errorf("kind = %v, want %v", rec["kind"], querylog.KindRead)
	}
	if rec["user"] != "testuser@example.com" {
		t.Errorf("user = %v, want testuser@example.com", rec["user"])
	}
	if rec["database"] != "waypoint_test" {
		t.Errorf("database = %v, want waypoint_test", rec["database"])
	}
	if rec["fingerprint"] == nil || rec["fingerprint"] == "" {
		t.Error("fingerprint is missing")
	}
	if rec["conn_id"] == nil || rec["conn_id"] == "" {
		t.Error("conn_id is missing")
	}
	if _, present := rec["statement"]; present {
		t.Errorf("statement text present at metadata level: %v", rec["statement"])
	}
	if rec["rows"] != float64(1) {
		t.Errorf("rows = %v, want 1", rec["rows"])
	}
}

// At normalized level the statement is logged with its constants elided.
func TestIntegration_Proxy_QueryLogNormalized(t *testing.T) {
	opt, cap := withQueryLog(t, config.QueryLogNormalized, config.QueryLogNormalized)
	addr := setupProxyWithAuth(t, &mockAuthorizer{result: queryLogAuthResult(nil)}, opt)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	ctx := context.Background()
	conn := proxyConnect(t, addr, "waypoint_test")
	var val int
	if err := conn.QueryRow(ctx, "SELECT 987654321").Scan(&val); err != nil {
		t.Fatalf("query: %v", err)
	}
	conn.Close(ctx)

	var found bool
	for _, rec := range cap.records(t) {
		stmt, _ := rec["statement"].(string)
		if !strings.Contains(stmt, "SELECT") {
			continue
		}
		found = true
		if strings.Contains(stmt, "987654321") {
			t.Errorf("normalized statement leaked the literal: %q", stmt)
		}
	}
	if !found {
		t.Error("no SELECT record was logged")
	}
}

// The listener ceiling holds even when a capability grant asks for more.
func TestIntegration_Proxy_QueryLogCeilingClampsACL(t *testing.T) {
	// The grant asks for full; the listener caps at normalized.
	result := queryLogAuthResult(&auth.LoggingCap{Queries: config.QueryLogFull})

	opt, cap := withQueryLog(t, config.QueryLogMetadata, config.QueryLogNormalized)
	addr := setupProxyWithAuth(t, &mockAuthorizer{result: result}, opt)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	ctx := context.Background()
	conn := proxyConnect(t, addr, "waypoint_test")
	var val int
	if err := conn.QueryRow(ctx, "SELECT 123456789").Scan(&val); err != nil {
		t.Fatalf("query: %v", err)
	}
	conn.Close(ctx)

	recs := cap.records(t)
	if len(recs) == 0 {
		t.Fatal("no records were logged")
	}
	for _, rec := range recs {
		stmt, _ := rec["statement"].(string)
		if strings.Contains(stmt, "123456789") {
			t.Errorf("grant escalated past the listener ceiling: %q", stmt)
		}
	}
}

// A grant may raise verbosity when the listener ceiling allows it.
func TestIntegration_Proxy_QueryLogACLRaisesWithinCeiling(t *testing.T) {
	result := queryLogAuthResult(&auth.LoggingCap{Queries: config.QueryLogFull})

	opt, cap := withQueryLog(t, config.QueryLogMetadata, config.QueryLogFull)
	addr := setupProxyWithAuth(t, &mockAuthorizer{result: result}, opt)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	ctx := context.Background()
	conn := proxyConnect(t, addr, "waypoint_test")
	var val int
	if err := conn.QueryRow(ctx, "SELECT 555000111").Scan(&val); err != nil {
		t.Fatalf("query: %v", err)
	}
	conn.Close(ctx)

	var sawLiteral bool
	for _, rec := range cap.records(t) {
		if stmt, _ := rec["statement"].(string); strings.Contains(stmt, "555000111") {
			sawLiteral = true
		}
	}
	if !sawLiteral {
		t.Error("grant did not raise logging to full within the listener ceiling")
	}
}

// With query logging off the relay must behave exactly as before — no records,
// and the connection still works.
func TestIntegration_Proxy_QueryLogOffEmitsNothing(t *testing.T) {
	opt, cap := withQueryLog(t, config.QueryLogOff, config.QueryLogOff)
	addr := setupProxyWithAuth(t, &mockAuthorizer{result: queryLogAuthResult(nil)}, opt)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	ctx := context.Background()
	conn := proxyConnect(t, addr, "waypoint_test")
	var val int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&val); err != nil {
		t.Fatalf("query: %v", err)
	}
	if val != 1 {
		t.Fatalf("expected 1, got %d", val)
	}
	conn.Close(ctx)

	if recs := cap.records(t); len(recs) != 0 {
		t.Errorf("query logging is off but %d records were emitted: %v", len(recs), recs)
	}
}

// A statement the backend rejects should still be logged, with the error.
func TestIntegration_Proxy_QueryLogRecordsBackendErrors(t *testing.T) {
	opt, cap := withQueryLog(t, config.QueryLogNormalized, config.QueryLogNormalized)
	addr := setupProxyWithAuth(t, &mockAuthorizer{result: queryLogAuthResult(nil)}, opt)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	ctx := context.Background()
	conn := proxyConnect(t, addr, "waypoint_test")
	var val int
	// Selecting from a table that does not exist produces a backend error.
	if err := conn.QueryRow(ctx, "SELECT id FROM public.qlog_absent_table").Scan(&val); err == nil {
		t.Fatal("expected the query to fail")
	}
	conn.Close(ctx)

	rec := cap.find(t, "qlog_absent_table")
	if rec == nil {
		t.Fatalf("no record for the failed statement; got %v", cap.records(t))
	}
	errStr, _ := rec["error"].(string)
	if !strings.Contains(errStr, "42P01") {
		t.Errorf("error = %q, want the undefined-table SQLSTATE 42P01", errStr)
	}
}

// Byte accounting must be unaffected by the taps: it is what enforces the
// per-user bandwidth limits, so a tap that swallowed or duplicated a byte
// would quietly corrupt limit enforcement.
func TestIntegration_Proxy_QueryLogPreservesByteAccounting(t *testing.T) {
	off := runQueryLogWorkload(t, config.QueryLogOff)
	full := runQueryLogWorkload(t, config.QueryLogFull)

	if off.read != full.read || off.written != full.written {
		t.Errorf("taps changed byte accounting: off=(read=%d, written=%d), full=(read=%d, written=%d)",
			off.read, off.written, full.read, full.written)
	}
	if off.read == 0 || off.written == 0 {
		t.Errorf("workload moved no bytes (read=%d, written=%d); the comparison proves nothing",
			off.read, off.written)
	}
}

type relayByteCounts struct{ read, written int64 }

// runQueryLogWorkload runs an identical workload at the given query log level
// and reports the bytes the relay accounted for.
func runQueryLogWorkload(t *testing.T, level string) relayByteCounts {
	t.Helper()

	opt, _ := withQueryLog(t, level, level)
	var read, written atomic.Int64

	addr := setupProxyWithAuth(t, &mockAuthorizer{result: queryLogAuthResult(nil)},
		opt,
		func(p *proxy.PostgresProxy) {
			p.BytesRead = &read
			p.BytesWritten = &written
		},
	)
	t.Cleanup(func() { cleanupRole(t, "testuser@example.com", "test-node", "waypoint_test") })

	ctx := context.Background()
	conn := proxyConnect(t, addr, "waypoint_test")
	for i := 0; i < 5; i++ {
		var val int
		if err := conn.QueryRow(ctx, "SELECT 1234").Scan(&val); err != nil {
			t.Fatalf("query: %v", err)
		}
	}
	conn.Close(ctx)

	// The proxy adds to the counters after the relay returns; give the
	// connection goroutine a moment to finish.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if read.Load() > 0 && written.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return relayByteCounts{read: read.Load(), written: written.Load()}
}

// withMongoQueryLog returns a proxy option enabling query logging on a
// MongoDB listener, capturing the records it produces.
func withMongoQueryLog(t *testing.T, level, maxLevel string) (func(*proxy.MongoDBProxy), *queryLogCapture) {
	t.Helper()

	cap := &queryLogCapture{}
	cap.emitter = querylog.NewEmitter(
		slog.New(slog.NewJSONHandler(cap, &slog.HandlerOptions{Level: slog.LevelDebug})),
		1024,
		querylog.Counters{},
	)
	t.Cleanup(cap.emitter.Close)

	return func(p *proxy.MongoDBProxy) {
		p.QueryLog = cap.emitter
		p.QueryLogConfig = &config.QueryLogConfig{Level: level, MaxLevel: maxLevel}
	}, cap
}

func TestIntegration_MongoProxy_QueryLog(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"qlogdb": {Permissions: []string{"readwrite"}},
	}, nil)

	opt, cap := withMongoQueryLog(t, config.QueryLogNormalized, config.QueryLogNormalized)
	addr := setupMongoProxyWithOpts(t, result, nil, opt)

	ctx := context.Background()
	client := mongoProxyConnect(t, addr, "qlogdb")
	coll := client.Database("qlogdb").Collection("widgets")

	if _, err := coll.InsertOne(ctx, bson.M{"name": "gadget", "serial": "SN-12345"}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var doc bson.M
	if err := coll.FindOne(ctx, bson.M{"name": "gadget"}).Decode(&doc); err != nil {
		t.Fatalf("find: %v", err)
	}
	if err := client.Disconnect(ctx); err != nil {
		t.Fatalf("disconnect: %v", err)
	}

	recs := cap.records(t)
	if len(recs) == 0 {
		t.Fatal("no query log records were emitted")
	}

	byOp := map[string]map[string]any{}
	for _, rec := range recs {
		if op, _ := rec["op"].(string); op != "" {
			byOp[op] = rec
		}
	}

	insert, ok := byOp["insert"]
	if !ok {
		t.Fatalf("no insert record; saw ops %v", opNames(recs))
	}
	if insert["collection"] != "widgets" {
		t.Errorf("insert collection = %v, want widgets", insert["collection"])
	}
	if insert["kind"] != querylog.KindWrite {
		t.Errorf("insert kind = %v, want %v", insert["kind"], querylog.KindWrite)
	}
	if insert["database"] != "qlogdb" {
		t.Errorf("insert database = %v, want qlogdb", insert["database"])
	}
	if insert["user"] != "testuser@example.com" {
		t.Errorf("insert user = %v, want testuser@example.com", insert["user"])
	}

	find, ok := byOp["find"]
	if !ok {
		t.Fatalf("no find record; saw ops %v", opNames(recs))
	}
	if find["collection"] != "widgets" {
		t.Errorf("find collection = %v, want widgets", find["collection"])
	}
	if find["kind"] != querylog.KindRead {
		t.Errorf("find kind = %v, want %v", find["kind"], querylog.KindRead)
	}
	if find["rows"] != float64(1) {
		t.Errorf("find rows = %v, want 1", find["rows"])
	}

	// At normalized level the command shape is logged, but the values the
	// client sent are not.
	for _, rec := range recs {
		stmt, _ := rec["statement"].(string)
		if strings.Contains(stmt, "SN-12345") || strings.Contains(stmt, "gadget") {
			t.Errorf("command shape leaked a value: %q", stmt)
		}
	}
}

func TestIntegration_MongoProxy_QueryLogOffEmitsNothing(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"qlogoffdb": {Permissions: []string{"readwrite"}},
	}, nil)

	opt, cap := withMongoQueryLog(t, config.QueryLogOff, config.QueryLogOff)
	addr := setupMongoProxyWithOpts(t, result, nil, opt)

	ctx := context.Background()
	client := mongoProxyConnect(t, addr, "qlogoffdb")
	if _, err := client.Database("qlogoffdb").Collection("t").InsertOne(ctx, bson.M{"a": 1}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := client.Disconnect(ctx); err != nil {
		t.Fatalf("disconnect: %v", err)
	}

	if recs := cap.records(t); len(recs) != 0 {
		t.Errorf("query logging is off but %d records were emitted: %v", len(recs), recs)
	}
}

func opNames(recs []map[string]any) []string {
	var out []string
	for _, rec := range recs {
		if op, _ := rec["op"].(string); op != "" {
			out = append(out, op)
		}
	}
	return out
}
