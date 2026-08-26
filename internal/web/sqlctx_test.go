package web

import (
	"reflect"
	"testing"
)

func TestSplitStatementsIgnoresQuotedSemicolons(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: "plain",
			sql:  "SELECT 1; SELECT 2",
			want: []string{"SELECT 1;", "SELECT 2"},
		},
		{
			name: "semicolon in string literal",
			sql:  "SELECT 'a;b'; SELECT 2",
			want: []string{"SELECT 'a;b';", "SELECT 2"},
		},
		{
			name: "semicolon in line comment",
			sql:  "SELECT 1 -- drop; me\n; SELECT 2",
			want: []string{"SELECT 1 -- drop; me\n;", "SELECT 2"},
		},
		{
			name: "semicolon in block comment",
			sql:  "SELECT /* a; b */ 1; SELECT 2",
			want: []string{"SELECT /* a; b */ 1;", "SELECT 2"},
		},
		{
			name: "dollar quoted body",
			sql:  "CREATE FUNCTION f() RETURNS int AS $$ BEGIN; RETURN 1; END; $$ LANGUAGE plpgsql; SELECT 2",
			want: []string{"CREATE FUNCTION f() RETURNS int AS $$ BEGIN; RETURN 1; END; $$ LANGUAGE plpgsql;", "SELECT 2"},
		},
		{
			name: "escaped quote inside literal",
			sql:  "SELECT 'it''s; fine'; SELECT 2",
			want: []string{"SELECT 'it''s; fine';", "SELECT 2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spans := splitStatements(tc.sql)
			var got []string
			for _, s := range spans {
				got = append(got, s.Text)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("splitStatements(%q)\n got %q\nwant %q", tc.sql, got, tc.want)
			}
		})
	}
}

func TestStatementAtPicksStatementUnderCursor(t *testing.T) {
	sql := "SELECT 1;\nSELECT 2;\nSELECT 3"
	// Caret inside the second statement.
	pos := len("SELECT 1;\nSELE")
	span, ok := statementAt(sql, pos)
	if !ok {
		t.Fatal("expected a statement")
	}
	if span.Text != "SELECT 2;" {
		t.Errorf("got %q, want %q", span.Text, "SELECT 2;")
	}
}

func TestExtractTablesCapturesAliases(t *testing.T) {
	got := extractTables("SELECT * FROM public.orders o JOIN customers AS c ON o.customer_id = c.id")
	want := []tableRef{
		{Schema: "public", Name: "orders", Alias: "o"},
		{Name: "customers", Alias: "c"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestExtractTablesCommaSeparated(t *testing.T) {
	got := extractTables("SELECT * FROM orders o, customers c WHERE 1=1")
	if len(got) != 2 || got[0].Name != "orders" || got[1].Name != "customers" {
		t.Errorf("got %+v", got)
	}
	if got[0].Alias != "o" || got[1].Alias != "c" {
		t.Errorf("aliases not captured: %+v", got)
	}
}

func TestAnalyzeCaret(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		caret     string // text the caret sits immediately after
		wantKind  completionKind
		wantQual  string
		wantPre   string
		wantAfter bool
	}{
		{
			name:     "after JOIN",
			sql:      "SELECT * FROM orders o JOIN ",
			caret:    "SELECT * FROM orders o JOIN ",
			wantKind: kindJoinTarget,
		},
		{
			name:     "after FROM",
			sql:      "SELECT * FROM ",
			caret:    "SELECT * FROM ",
			wantKind: kindTable,
		},
		{
			name:     "qualified column",
			sql:      "SELECT o. FROM orders o",
			caret:    "SELECT o.",
			wantKind: kindColumnOf,
			wantQual: "o",
		},
		{
			name:     "qualified column with prefix",
			sql:      "SELECT o.cust FROM orders o",
			caret:    "SELECT o.cust",
			wantKind: kindColumnOf,
			wantQual: "o",
			wantPre:  "cust",
		},
		{
			name:      "inside ON predicate",
			sql:       "SELECT * FROM orders o JOIN customers c ON ",
			caret:     "SELECT * FROM orders o JOIN customers c ON ",
			wantKind:  kindExpression,
			wantAfter: true,
		},
		{
			name:     "select list is an expression",
			sql:      "SELECT  FROM orders o",
			caret:    "SELECT ",
			wantKind: kindExpression,
		},
		{
			// A bare relation name cannot start a statement, so an empty
			// buffer must offer verbs rather than table names.
			name:     "empty buffer starts a statement",
			sql:      "",
			caret:    "",
			wantKind: kindStatementStart,
		},
		{
			name:     "partial first word starts a statement",
			sql:      "sel",
			caret:    "sel",
			wantKind: kindStatementStart,
			wantPre:  "sel",
		},
		{
			name:     "statement start after a semicolon",
			sql:      "SELECT 1;\n",
			caret:    "SELECT 1;\n",
			wantKind: kindStatementStart,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pos := len(tc.caret)
			got := analyzeCaret(tc.sql, pos)
			if got.Kind != tc.wantKind {
				t.Errorf("kind = %v, want %v", got.Kind, tc.wantKind)
			}
			if got.Qualifier != tc.wantQual {
				t.Errorf("qualifier = %q, want %q", got.Qualifier, tc.wantQual)
			}
			if got.Prefix != tc.wantPre {
				t.Errorf("prefix = %q, want %q", got.Prefix, tc.wantPre)
			}
			if got.AfterOn != tc.wantAfter {
				t.Errorf("afterOn = %v, want %v", got.AfterOn, tc.wantAfter)
			}
		})
	}
}

func TestAnalyzeCaretUsesStatementUnderCursor(t *testing.T) {
	sql := "SELECT * FROM customers;\nSELECT * FROM orders o JOIN "
	ctx := analyzeCaret(sql, len(sql))
	if ctx.Kind != kindJoinTarget {
		t.Fatalf("kind = %v, want kindJoinTarget", ctx.Kind)
	}
	// Only the second statement's tables should be in scope.
	if len(ctx.Tables) != 1 || ctx.Tables[0].Name != "orders" {
		t.Errorf("tables = %+v, want just orders", ctx.Tables)
	}
}

func TestGenerateAliasAvoidsCollisions(t *testing.T) {
	used := map[string]bool{"c": true, "c1": true}
	if got := generateAlias("customers", used); got != "c2" {
		t.Errorf("got %q, want c2", got)
	}
	if got := generateAlias("orders", map[string]bool{}); got != "o" {
		t.Errorf("got %q, want o", got)
	}
}

func TestRenderJoinPathSingleHop(t *testing.T) {
	p := joinPath{
		target: TableInfo{Schema: "public", Name: "customers"},
		steps: []joinStep{{
			from:    "o",
			table:   TableInfo{Schema: "public", Name: "customers"},
			srcCols: []string{"customer_id"},
			tgtCols: []string{"id"},
		}},
	}
	apply, detail := renderJoinPath(p, map[string]bool{"o": true})
	want := "customers ${c} ON o.customer_id = ${c}.id"
	if apply != want {
		t.Errorf("apply = %q, want %q", apply, want)
	}
	if detail != "via foreign key" {
		t.Errorf("detail = %q", detail)
	}
}

func TestRenderJoinPathCompositeKey(t *testing.T) {
	p := joinPath{
		target: TableInfo{Schema: "public", Name: "order_items"},
		steps: []joinStep{{
			from:    "o",
			table:   TableInfo{Schema: "public", Name: "order_items"},
			srcCols: []string{"order_id", "tenant_id"},
			tgtCols: []string{"id", "tenant"},
		}},
	}
	apply, _ := renderJoinPath(p, map[string]bool{"o": true})
	want := "order_items ${o1} ON o.order_id = ${o1}.id AND o.tenant_id = ${o1}.tenant"
	if apply != want {
		t.Errorf("apply = %q,\n want %q", apply, want)
	}
}

func TestPermsFingerprintIsOrderIndependent(t *testing.T) {
	a := permsFingerprintFor([]string{"readonly", "readwrite"}, []string{"public"})
	b := permsFingerprintFor([]string{"readwrite", "readonly"}, []string{"public"})
	if a != b {
		t.Errorf("fingerprint changed with ordering: %s vs %s", a, b)
	}
	c := permsFingerprintFor([]string{"readonly"}, []string{"public"})
	if a == c {
		t.Error("fingerprint did not change when permissions changed")
	}
}

func TestLabelSegments(t *testing.T) {
	tests := []struct {
		label string
		want  []string
	}{
		{"customer_id", []string{"customer", "id"}},
		{"o.customer_id", []string{"o", "customer", "id"}},
		{"GROUP BY", []string{"group", "by"}},
		{"createdAt", []string{"created", "at"}},
		{"IS NOT NULL", []string{"is", "not", "null"}},
		{"orders", []string{"orders"}},
	}
	for _, tc := range tests {
		got := labelSegments(tc.label)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("labelSegments(%q) = %v, want %v", tc.label, got, tc.want)
		}
	}
}

func TestMatchLabel(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		pattern string
		want    bool
	}{
		{"exact", "orders", "orders", true},
		{"whole prefix", "customers", "cust", true},
		{"after a qualifier", "o.customer_id", "cust", true},
		{"snake_case word", "created_at", "at", true},
		{"multi-word keyword", "GROUP BY", "by", true},
		{"camelCase hump", "createdAt", "at", true},
		{"initials", "created_at", "ca", true},
		{"case insensitive", "SELECT", "sel", true},

		// The substring fallback these replace matched all of the following,
		// which is why a single vowel used to return most of the catalog.
		{"interior letter is not a match", "c.created_at", "e", false},
		{"interior run is not a match", "customers", "tome", false},
		{"interior word fragment", "shipments", "ment", false},
		// A single letter still matches the start of a word — that is what
		// people expect when they type one character. What it must not do is
		// match anywhere inside a word, which is the case above.
		{"single letter matches a word start", "created_at", "c", true},
		{"single letter does not match mid-word", "created_at", "r", false},
		{"initials need two characters", "created_at", "a", true},
		{"prefix beats the initials tier", "orders", "or", true},
		{"longer than the label", "id", "identifier", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, got := matchLabel(tc.label, tc.pattern)
			if got != tc.want {
				t.Errorf("matchLabel(%q, %q) = %v, want %v", tc.label, tc.pattern, got, tc.want)
			}
		})
	}
}

func TestMatchLabelRanksPrefixAboveSegment(t *testing.T) {
	prefixScore, ok := matchLabel("customers", "cust")
	if !ok {
		t.Fatal("expected a prefix match")
	}
	segScore, ok := matchLabel("order_customers", "cust")
	if !ok {
		t.Fatal("expected a segment match")
	}
	if prefixScore <= segScore {
		t.Errorf("prefix match (%v) should outrank segment match (%v)", prefixScore, segScore)
	}
}
