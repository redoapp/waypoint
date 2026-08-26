//go:build integration

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/testutil"
)

// The console's editor assistance and execution paths are exercised here
// against a real Postgres. Identity resolution is the one part that cannot be
// covered without a tailnet, so these tests drive the layers beneath it with a
// pool built directly, which is exactly what the HTTP handlers hand down.

const schemaDDL = `
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
CREATE TYPE order_status AS ENUM ('pending', 'shipped');
CREATE TABLE customers (id bigserial PRIMARY KEY, email text, name text);
COMMENT ON COLUMN customers.email IS 'Primary contact address.';
CREATE TABLE orders (
    id bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(id),
    total numeric,
    status order_status NOT NULL DEFAULT 'pending'
);
CREATE TABLE shipments (
    id bigserial PRIMARY KEY,
    order_id bigint NOT NULL REFERENCES orders(id),
    carrier text
);
CREATE TABLE labels (
    id bigserial PRIMARY KEY,
    shipment_id bigint NOT NULL REFERENCES shipments(id),
    tracking text
);
CREATE TABLE order_items (
    order_id bigint NOT NULL REFERENCES orders(id),
    sku text NOT NULL,
    qty int,
    PRIMARY KEY (order_id, sku)
);
-- A genuine two-column foreign key. A composite PRIMARY key would not
-- exercise the paired-predicate path; only a composite FOREIGN key does.
CREATE TABLE item_returns (
    id bigserial PRIMARY KEY,
    order_id bigint NOT NULL,
    sku text NOT NULL,
    FOREIGN KEY (order_id, sku) REFERENCES order_items(order_id, sku)
);
INSERT INTO customers (email, name) VALUES ('a@example.com', 'Ann'), ('b@example.com', 'Bo');
INSERT INTO orders (customer_id, total) VALUES (1, 10.50), (1, 22.00), (2, 3.75);
`

// testConsole builds a Server plus a pool connected as a restricted role:
// SELECT everywhere, INSERT only on orders. That asymmetry is what the
// permission diagnostics are checked against.
func testConsole(t *testing.T) (*Server, *pgxpool.Pool, string) {
	t.Helper()
	connStr, _ := testutil.PostgresBackend(t)
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, connStr)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)

	// Use the console's own splitter rather than strings.Split(";"): the DDL
	// below has a semicolon inside a comment, which a naive split would cut
	// the statement in half on.
	for _, span := range splitStatements(schemaDDL) {
		stmt := strings.TrimSuffix(strings.TrimSpace(span.Text), ";")
		if stmt == "" {
			continue
		}
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("ddl %q: %v", stmt, err)
		}
	}

	role := fmt.Sprintf("wp_console_%d", time.Now().UnixNano()%1e6)
	grants := []string{
		fmt.Sprintf("DROP ROLE IF EXISTS %s", role),
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD 'consolepw'", role),
		fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s", role),
		fmt.Sprintf("GRANT SELECT ON ALL TABLES IN SCHEMA public TO %s", role),
		fmt.Sprintf("GRANT INSERT ON orders TO %s", role),
	}
	for _, g := range grants {
		if _, err := admin.Exec(ctx, g); err != nil {
			t.Fatalf("grant %q: %v", g, err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), connStr)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "REASSIGN OWNED BY "+role+" TO admin")
		_, _ = c.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = c.Exec(context.Background(), "DROP ROLE IF EXISTS "+role)
	})

	userConn := strings.Replace(connStr, "admin:adminpass", role+":consolepw", 1)
	pool, err := pgxpool.New(ctx, userConn)
	if err != nil {
		t.Fatalf("user pool: %v", err)
	}
	t.Cleanup(pool.Close)

	s := &Server{
		name:        "console-test",
		backend:     "127.0.0.1:5432",
		databases:   []string{"waypoint_test"},
		catalog:     newCatalogCache(time.Minute),
		webCfg:      &config.WebConfig{MaxRows: 100},
		queryLogCfg: &config.QueryLogConfig{},
		logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	return s, pool, role
}

func TestIntegrationCatalogIsPermissionScoped(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	cat, err := s.catalog.Get(ctx, "k", pool)
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}

	byName := map[string]TableInfo{}
	for _, tb := range cat.Tables {
		byName[tb.Name] = tb
	}

	orders, ok := byName["orders"]
	if !ok {
		t.Fatal("orders not in catalog")
	}
	if !orders.Select || !orders.Insert {
		t.Errorf("orders privileges = %+v, want select+insert", orders)
	}
	customers, ok := byName["customers"]
	if !ok {
		t.Fatal("customers not in catalog")
	}
	if !customers.Select {
		t.Error("customers should be selectable")
	}
	if customers.Insert || customers.Update || customers.Delete {
		t.Errorf("customers should be read-only, got %+v", customers)
	}

	// The FK graph must survive introspection, including direction.
	found := false
	for _, fk := range cat.ForeignKeys {
		if fk.SrcTable == "orders" && fk.TgtTable == "customers" {
			found = true
			if len(fk.SrcCols) != 1 || fk.SrcCols[0] != "customer_id" {
				t.Errorf("src cols = %v", fk.SrcCols)
			}
			if len(fk.TgtCols) != 1 || fk.TgtCols[0] != "id" {
				t.Errorf("tgt cols = %v", fk.TgtCols)
			}
		}
	}
	if !found {
		t.Errorf("orders→customers FK missing; got %+v", cat.ForeignKeys)
	}
}

func TestIntegrationCompleteJoinInsertsOnClause(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	sql := "SELECT * FROM orders o JOIN "
	res, err := s.complete(ctx, pool, "k", sql, len(sql))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	var customers *Completion
	for i := range res.Options {
		if res.Options[i].Label == "customers" {
			customers = &res.Options[i]
			break
		}
	}
	if customers == nil {
		t.Fatalf("customers not offered; got %d options", len(res.Options))
	}
	want := "customers ${c} ON o.customer_id = ${c}.id"
	if customers.Apply != want {
		t.Errorf("apply = %q, want %q", customers.Apply, want)
	}
	if customers.Detail != "via foreign key" {
		t.Errorf("detail = %q", customers.Detail)
	}
}

func TestIntegrationCompleteCompositeForeignKeyJoin(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	sql := "SELECT * FROM order_items oi JOIN "
	res, err := s.complete(ctx, pool, "k", sql, len(sql))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	for _, o := range res.Options {
		if o.Label != "item_returns" {
			continue
		}
		// Both column pairs must appear, AND-ed, and paired in the order the
		// constraint declares them.
		want := "item_returns ${i} ON oi.order_id = ${i}.order_id AND oi.sku = ${i}.sku"
		if o.Apply != want {
			t.Errorf("apply = %q,\n want %q", o.Apply, want)
		}
		return
	}
	var labels []string
	for _, o := range res.Options {
		labels = append(labels, o.Label)
	}
	cat, _ := s.catalog.Get(ctx, "k", pool)
	var tables []string
	for _, tb := range cat.Tables {
		tables = append(tables, tb.Qualified())
	}
	t.Fatalf("item_returns not offered as a join target.\n  options: %v\n  catalog: %v\n  fks: %+v",
		labels, tables, cat.ForeignKeys)
}

func TestIntegrationCompleteMultiHopJoinPath(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	// labels reaches orders only through shipments.
	sql := "SELECT * FROM labels l JOIN "
	res, err := s.complete(ctx, pool, "k", sql, len(sql))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	var orders *Completion
	for i := range res.Options {
		if res.Options[i].Label == "orders" {
			orders = &res.Options[i]
			break
		}
	}
	if orders == nil {
		t.Fatal("orders not offered as a multi-hop join target")
	}
	if !strings.Contains(orders.Apply, "shipments") {
		t.Errorf("multi-hop path should join through shipments, got %q", orders.Apply)
	}
	if !strings.Contains(orders.Apply, "JOIN orders") {
		t.Errorf("multi-hop path should end at orders, got %q", orders.Apply)
	}
	if !strings.Contains(orders.Detail, "→") {
		t.Errorf("detail should describe the hops, got %q", orders.Detail)
	}
}

func TestIntegrationCompleteStatementStartOffersVerbs(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	for _, sql := range []string{"", "sel", "SELECT 1;\n"} {
		res, err := s.complete(ctx, pool, "k", sql, len(sql))
		if err != nil {
			t.Fatalf("complete(%q): %v", sql, err)
		}
		if len(res.Options) == 0 {
			t.Fatalf("complete(%q): no options", sql)
		}
		// A relation name cannot begin a statement, so only verbs belong
		// here — and with a single tier the section label is dropped, which
		// is why this asserts on the options rather than on Section.
		// SELECT must lead: equal boosts tie-break alphabetically, which
		// would surface DELETE FROM first.
		if got := res.Options[0].Label; got != "SELECT" {
			t.Errorf("complete(%q): first option = %q, want SELECT", sql, got)
		}
		for _, o := range res.Options {
			if o.Type == "table" || o.Type == "view" {
				t.Errorf("complete(%q): relation %q offered at statement start", sql, o.Label)
			}
		}
	}
}

func TestIntegrationCompleteSectionsOrderByRelevance(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	// Mid-expression with relations in scope: columns of those relations are
	// the most likely thing wanted, and must outrank unrelated relations and
	// keywords no matter how well those match what has been typed.
	sql := "SELECT  FROM orders o JOIN customers c ON o.customer_id = c.id"
	res, err := s.complete(ctx, pool, "k", sql, len("SELECT "))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if len(res.Options) == 0 {
		t.Fatal("no options")
	}
	if got := res.Options[0].Section; got != sectionColumns {
		t.Errorf("first section = %q, want %q", got, sectionColumns)
	}

	// Sections must come back grouped and in rank order, because the cap
	// truncates the tail and the client relies on the ranks.
	lastRank := 0
	for _, o := range res.Options {
		if o.SectionRank < lastRank {
			t.Fatalf("section ranks out of order at %q: %d after %d",
				o.Label, o.SectionRank, lastRank)
		}
		lastRank = o.SectionRank
	}
}

func TestIntegrationCompleteQualifiesWithAliasNotTableName(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	// Two relations in scope, both aliased. Postgres rejects the original
	// table name once a relation is aliased, so completing "orders.id" here
	// would insert SQL that cannot run:
	//   SELECT orders.id FROM orders o
	//   ERROR 42P01: invalid reference to FROM-clause entry for table "orders"
	sql := "SELECT  FROM orders o JOIN customers c ON o.customer_id = c.id"
	res, err := s.complete(ctx, pool, "k", sql, len("SELECT "))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	var qualified []string
	for _, o := range res.Options {
		if o.DisplayLabel == "" {
			continue
		}
		qualified = append(qualified, o.DisplayLabel)

		// The bare name has to stay in Label: CodeMirror matches a
		// single-character query only against position 0, so a qualified
		// Label would make "e" unable to reach c.email.
		if strings.Contains(o.Label, ".") {
			t.Errorf("Label %q carries a qualifier; it belongs in DisplayLabel", o.Label)
		}
		if o.Apply != o.DisplayLabel {
			t.Errorf("option %q inserts %q; want the qualified form", o.DisplayLabel, o.Apply)
		}
	}
	if len(qualified) == 0 {
		t.Fatal("expected qualified column labels with two relations in scope")
	}
	for _, label := range qualified {
		prefix := label[:strings.Index(label, ".")]
		switch prefix {
		case "o", "c":
		default:
			t.Errorf("column %q is qualified with %q; want the alias o or c", label, prefix)
		}
	}
}

func TestIntegrationCompleteSingleCharacterReachesQualifiedColumn(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	// Typing one letter must still reach a column on an aliased relation.
	// This is the case that qualifying the label broke: CodeMirror drops a
	// single-character query unless it matches at position 0.
	sql := "SELECT e FROM orders o JOIN customers c ON o.customer_id = c.id"
	res, err := s.complete(ctx, pool, "k", sql, len("SELECT e"))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	for _, o := range res.Options {
		if o.DisplayLabel == "c.email" {
			if o.Label != "email" {
				t.Errorf("Label = %q, want the bare name so a single char matches at position 0", o.Label)
			}
			return
		}
	}
	t.Errorf("c.email not offered for a single-character query; got %d options", len(res.Options))
}

func TestIntegrationCompleteAliasQualifiedColumnsAreValidSQL(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	// Take what the console would insert and hand it straight to Postgres.
	sql := "SELECT  FROM orders o JOIN customers c ON o.customer_id = c.id"
	res, err := s.complete(ctx, pool, "k", sql, len("SELECT "))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	// Use Apply — the text the editor actually inserts — rather than Label,
	// which deliberately holds the bare name for matching.
	var pick string
	for _, o := range res.Options {
		if strings.HasPrefix(o.Apply, "o.") {
			pick = o.Apply
			break
		}
	}
	if pick == "" {
		t.Fatal("no alias-qualified column offered")
	}

	built := "SELECT " + pick + " FROM orders o JOIN customers c ON o.customer_id = c.id"
	for _, f := range execFrames(t, s, pool, built) {
		if f["type"] == "error" {
			t.Fatalf("completing %q produced SQL postgres rejects: [%v] %v",
				pick, f["code"], f["message"])
		}
	}
}

func TestIntegrationCompleteFiltersOnWordBoundaries(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	base := "SELECT %s FROM orders o JOIN customers c ON o.customer_id = c.id"

	// A single interior vowel used to match nearly the whole catalog through
	// the substring fallback: every keyword and identifier containing an "e"
	// anywhere came back.
	sqlAll := fmt.Sprintf(base, "")
	all, err := s.complete(ctx, pool, "k", sqlAll, len("SELECT "))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	sqlE := fmt.Sprintf(base, "e")
	narrowed, err := s.complete(ctx, pool, "k", sqlE, len("SELECT e"))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if len(narrowed.Options) >= len(all.Options) {
		t.Errorf("typing a letter did not narrow the list: %d of %d",
			len(narrowed.Options), len(all.Options))
	}
	for _, o := range narrowed.Options {
		if _, ok := matchLabel(o.Label, "e"); !ok {
			t.Errorf("%q survived the filter without matching a word boundary", o.Label)
		}
	}
	t.Logf("unfiltered %d options; typing \"e\" narrows to %d", len(all.Options), len(narrowed.Options))

	// Word-boundary matching still has to reach the things people mean.
	for _, tc := range []struct{ typed, want string }{
		{"cust", "c.id"},     // a customers column, via the alias tail
		{"em", "c.email"},    // a whole-word prefix
		{"stat", "o.status"}, // a whole-word prefix on the other relation
	} {
		sql := fmt.Sprintf(base, tc.typed)
		res, err := s.complete(ctx, pool, "k", sql, len("SELECT ")+len(tc.typed))
		if err != nil {
			t.Fatalf("complete(%q): %v", tc.typed, err)
		}
		if len(res.Options) == 0 {
			t.Errorf("typing %q returned nothing", tc.typed)
		}
	}
}

func TestIntegrationCompleteSingleSectionIsUnlabelled(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	// Everything after "o." is a column, so a section header would be noise.
	sql := "SELECT o. FROM orders o"
	res, err := s.complete(ctx, pool, "k", sql, len("SELECT o."))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	for _, o := range res.Options {
		if o.Section != "" {
			t.Errorf("option %q carries section %q in a single-tier result", o.Label, o.Section)
		}
	}
}

func TestIntegrationCompleteQualifiedColumns(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	sql := "SELECT o. FROM orders o"
	res, err := s.complete(ctx, pool, "k", sql, len("SELECT o."))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	labels := map[string]bool{}
	for _, o := range res.Options {
		labels[o.Label] = true
	}
	for _, want := range []string{"id", "customer_id", "total"} {
		if !labels[want] {
			t.Errorf("missing column %q; got %v", want, labels)
		}
	}
	if labels["email"] {
		t.Error("customers.email leaked into orders completion")
	}
}

func TestIntegrationCompleteColumnCarriesComment(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	sql := "SELECT c. FROM customers c"
	res, err := s.complete(ctx, pool, "k", sql, len("SELECT c."))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	for _, o := range res.Options {
		if o.Label == "email" {
			if !strings.Contains(o.Info, "Primary contact address.") {
				t.Errorf("column comment missing from info: %q", o.Info)
			}
			return
		}
	}
	t.Fatal("email column not offered")
}

func TestIntegrationDiagnosticsFlagDisallowedWrite(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	// INSERT on orders is granted; UPDATE on customers is not.
	diags := s.diagnose(ctx, pool, "k", "UPDATE customers SET name = 'x' WHERE id = 1")
	var found bool
	for _, d := range diags {
		if d.Source == "permission" && strings.Contains(d.Message, "UPDATE") && strings.Contains(d.Message, "customers") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an UPDATE permission warning, got %+v", diags)
	}

	// The permitted write must not warn.
	ok := s.diagnose(ctx, pool, "k", "INSERT INTO orders (customer_id) VALUES (1)")
	for _, d := range ok {
		if d.Source == "permission" && strings.Contains(d.Message, "INSERT") {
			t.Errorf("permitted INSERT was flagged: %+v", d)
		}
	}
}

func TestIntegrationDiagnosticsSyntaxAndShape(t *testing.T) {
	s, pool, _ := testConsole(t)
	ctx := context.Background()

	sql := "SELECT id, FROM orders"
	diags := s.diagnose(ctx, pool, "k", sql)
	if len(diags) == 0 || diags[0].Severity != "error" {
		t.Fatalf("expected a syntax error, got %+v", diags)
	}
	if diags[0].From < 0 || diags[0].To > len(sql) || diags[0].From >= diags[0].To {
		t.Errorf("syntax error range %d..%d is not inside the buffer (len %d)", diags[0].From, diags[0].To, len(sql))
	}

	shape := s.diagnose(ctx, pool, "k", "DELETE FROM orders")
	var warned bool
	for _, d := range shape {
		if d.Source == "shape" && strings.Contains(d.Message, "WHERE") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected an unqualified DELETE warning, got %+v", shape)
	}
}

// execFrames runs a statement through the streaming path and returns the
// decoded frames, which is exactly what the browser consumes.
func execFrames(t *testing.T, s *Server, pool *pgxpool.Pool, stmt string) []map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	out := newNDJSON(rec)
	sess := &session{Auth: testAuthResult(), ReqID: "test"}
	if err := s.execute(context.Background(), out, pool, sess, "waypoint_test", stmt); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var frames []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(rec.Body.Bytes()), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var f map[string]any
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("decode frame %q: %v", line, err)
		}
		frames = append(frames, f)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	return frames
}

func TestIntegrationExecuteStreamsPidThenRows(t *testing.T) {
	s, pool, _ := testConsole(t)
	frames := execFrames(t, s, pool, "SELECT id, total FROM orders ORDER BY id")

	if frames[0]["type"] != "begin" {
		t.Fatalf("first frame is %v, want begin", frames[0]["type"])
	}
	// The PID must arrive before any rows: that is what lets the browser
	// cancel a query without the server tracking it.
	if pid, _ := frames[0]["pid"].(float64); pid <= 0 {
		t.Errorf("begin frame carried no pid: %+v", frames[0])
	}
	if frames[1]["type"] != "columns" {
		t.Fatalf("second frame is %v, want columns", frames[1]["type"])
	}

	total := 0
	var end map[string]any
	for _, f := range frames[2:] {
		switch f["type"] {
		case "rows":
			total += len(f["rows"].([]any))
		case "end":
			end = f
		}
	}
	if total != 3 {
		t.Errorf("streamed %d rows, want 3", total)
	}
	if end == nil {
		t.Fatal("no end frame")
	}
	if rc, _ := end["rowCount"].(float64); int(rc) != 3 {
		t.Errorf("rowCount = %v, want 3", end["rowCount"])
	}
}

func TestIntegrationExecuteNamesUserDefinedTypes(t *testing.T) {
	s, pool, _ := testConsole(t)
	frames := execFrames(t, s, pool, "SELECT id, status FROM orders LIMIT 1")

	var cols []any
	for _, f := range frames {
		if f["type"] == "columns" {
			cols = f["columns"].([]any)
		}
	}
	if len(cols) != 2 {
		t.Fatalf("expected 2 columns, got %+v", cols)
	}
	// pgx's type map has no entry for an enum, so without an explicit lookup
	// this column would be headed "oid:16630" in the grid.
	got := cols[1].(map[string]any)["type"]
	if got != "order_status" {
		t.Errorf("status column type = %v, want order_status", got)
	}
}

func TestIntegrationExecuteRowCapTruncates(t *testing.T) {
	s, pool, _ := testConsole(t)
	s.webCfg = &config.WebConfig{MaxRows: 2}

	frames := execFrames(t, s, pool, "SELECT id FROM orders ORDER BY id")
	var end map[string]any
	rows := 0
	for _, f := range frames {
		if f["type"] == "rows" {
			rows += len(f["rows"].([]any))
		}
		if f["type"] == "end" {
			end = f
		}
	}
	if rows != 2 {
		t.Errorf("returned %d rows, want the cap of 2", rows)
	}
	if end == nil || end["truncated"] != true {
		t.Errorf("expected truncated=true, got %+v", end)
	}
}

func TestIntegrationExecuteReportsErrorPosition(t *testing.T) {
	s, pool, _ := testConsole(t)
	frames := execFrames(t, s, pool, "SELECT id, totl FROM orders")

	var errFrame map[string]any
	for _, f := range frames {
		if f["type"] == "error" {
			errFrame = f
		}
	}
	if errFrame == nil {
		t.Fatal("expected an error frame")
	}
	if errFrame["code"] != "42703" {
		t.Errorf("code = %v, want 42703", errFrame["code"])
	}
	if pos, _ := errFrame["position"].(float64); pos <= 0 {
		t.Errorf("no error position reported: %+v", errFrame)
	}
}

func TestIntegrationExecuteDeniedWriteSurfacesPostgresError(t *testing.T) {
	s, pool, _ := testConsole(t)
	// The linter warns about this; Postgres is what actually refuses it.
	frames := execFrames(t, s, pool, "UPDATE customers SET name = 'x' WHERE id = 1")

	var errFrame map[string]any
	for _, f := range frames {
		if f["type"] == "error" {
			errFrame = f
		}
	}
	if errFrame == nil {
		t.Fatal("expected the database to reject the write")
	}
	if errFrame["code"] != "42501" {
		t.Errorf("code = %v, want 42501 (insufficient privilege)", errFrame["code"])
	}
}

func TestIntegrationCancelStopsRunningQuery(t *testing.T) {
	s, pool, role := testConsole(t)
	ctx := context.Background()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()

	var pid int32
	if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatalf("pid: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := conn.Exec(ctx, "SELECT pg_sleep(30)")
		done <- err
	}()

	// Give the sleep time to register in pg_stat_activity.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		_ = pool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE pid = $1 AND state = 'active'", pid).Scan(&n)
		if n > 0 {
			break
		}
	}

	if err := s.cancel(ctx, pool, role, pid); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "canceling statement") {
			t.Errorf("query ended with %v, want a cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("query was not cancelled")
	}

	// A cancelled connection must stay usable, or the pool would leak it.
	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Errorf("connection unusable after cancel: %v", err)
	}
}

func TestIntegrationCancelRejectsForeignBackend(t *testing.T) {
	s, pool, role := testConsole(t)
	ctx := context.Background()

	// A PID belonging to some other role must not be cancellable, even
	// though Postgres would also refuse: the endpoint should not be usable
	// to probe which PIDs exist.
	var otherPID int32
	err := pool.QueryRow(ctx,
		"SELECT pid FROM pg_stat_activity WHERE usename IS NOT NULL AND usename <> $1 LIMIT 1", role).Scan(&otherPID)
	if err != nil {
		t.Skip("no other backend to test against")
	}
	if err := s.cancel(ctx, pool, role, otherPID); err == nil {
		t.Error("cancel accepted a backend belonging to another role")
	}
}
