package querylog

import (
	"reflect"
	"strings"
	"testing"
)

func TestAnalyze_VerbAndKind(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantVerb string
		wantKind string
	}{
		{"select", "SELECT * FROM orders", "SELECT", KindRead},
		{"select constant", "SELECT 1", "SELECT", KindRead},
		{"explain is a read", "EXPLAIN SELECT * FROM orders WHERE id = 1", "EXPLAIN", KindRead},
		{"insert", "INSERT INTO t VALUES (1)", "INSERT", KindWrite},
		{"update", "UPDATE t SET a = 1", "UPDATE", KindWrite},
		{"delete", "DELETE FROM t WHERE id = 1", "DELETE", KindWrite},
		{"truncate", "TRUNCATE TABLE t", "TRUNCATE", KindWrite},
		{"create table", "CREATE TABLE foo (id INT)", "CREATE TABLE", KindDDL},
		{"drop table", "DROP TABLE foo", "DROP TABLE", KindDDL},
		{"alter table", "ALTER TABLE t ADD COLUMN c INT", "ALTER TABLE", KindDDL},
		{"grant is dcl", "GRANT SELECT ON t TO bob", "GRANT", KindDCL},
		{"begin is tcl", "BEGIN", "BEGIN", KindTCL},
		{"commit is tcl", "COMMIT", "COMMIT", KindTCL},
		{"set is a utility not a write", "SET search_path = 'x'", "SET", KindUtility},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := analyze(tt.sql)
			if m.ParseError {
				t.Fatalf("analyze(%q) failed to parse", tt.sql)
			}
			if m.Verb != tt.wantVerb {
				t.Errorf("verb = %q, want %q", m.Verb, tt.wantVerb)
			}
			if m.Kind != tt.wantKind {
				t.Errorf("kind = %q, want %q", m.Kind, tt.wantKind)
			}
		})
	}
}

// TestAnalyze_Tables is the contract for table extraction. The extraction
// itself rides on the formatter's traversal, so this table is what pins the
// behavior we actually depend on.
func TestAnalyze_Tables(t *testing.T) {
	tests := []struct {
		name       string
		sql        string
		wantTables []string
		wantWrite  string
	}{
		{
			name:       "plain from",
			sql:        "SELECT * FROM orders WHERE id = 42",
			wantTables: []string{"orders"},
		},
		{
			name:       "join collects both sides",
			sql:        "SELECT o.* FROM orders o JOIN users u ON u.id = o.user_id",
			wantTables: []string{"orders", "users"},
		},
		{
			name:       "comma join",
			sql:        "SELECT * FROM a, b",
			wantTables: []string{"a", "b"},
		},
		{
			name:       "subquery in select list",
			sql:        "SELECT (SELECT max(x) FROM inner_t) FROM outer_t",
			wantTables: []string{"inner_t", "outer_t"},
		},
		{
			name:       "cte name excluded, underlying table kept",
			sql:        "WITH recent AS (SELECT * FROM orders) SELECT * FROM recent JOIN users ON true",
			wantTables: []string{"orders", "users"},
		},
		{
			name:       "insert select records target and source",
			sql:        "INSERT INTO t (a, b) SELECT a, b FROM src",
			wantTables: []string{"src", "t"},
			wantWrite:  "t",
		},
		{
			name:       "update from",
			sql:        "UPDATE t SET a = 1 FROM other WHERE t.id = other.id",
			wantTables: []string{"other", "t"},
			wantWrite:  "t",
		},
		{
			name:       "delete",
			sql:        "DELETE FROM sessions WHERE id = 1",
			wantTables: []string{"sessions"},
			wantWrite:  "sessions",
		},
		{
			name:       "truncate",
			sql:        "TRUNCATE TABLE big",
			wantTables: []string{"big"},
			wantWrite:  "big",
		},
		{
			name:       "create table",
			sql:        "CREATE TABLE foo (id INT PRIMARY KEY)",
			wantTables: []string{"foo"},
		},
		{
			name:       "drop multiple tables",
			sql:        "DROP TABLE a, b",
			wantTables: []string{"a", "b"},
		},
		{
			name:       "schema qualified name is preserved",
			sql:        "SELECT * FROM public.orders",
			wantTables: []string{"public.orders"},
		},
		{
			name:       "three part name is preserved",
			sql:        "SELECT * FROM db.sch.tbl",
			wantTables: []string{"db.sch.tbl"},
		},
		{
			name:       "quoted identifier keeps its quoting",
			sql:        `SELECT * FROM "MixedCase"`,
			wantTables: []string{`"MixedCase"`},
		},
		{
			name:       "explain descends into the explained statement",
			sql:        "EXPLAIN SELECT * FROM orders",
			wantTables: []string{"orders"},
		},
		{
			name:       "no table at all",
			sql:        "SELECT 1",
			wantTables: nil,
		},
		{
			name:       "duplicate references are deduped",
			sql:        "SELECT * FROM t WHERE id IN (SELECT id FROM t)",
			wantTables: []string{"t"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := analyze(tt.sql)
			if m.ParseError {
				t.Fatalf("analyze(%q) failed to parse", tt.sql)
			}
			if !reflect.DeepEqual(m.Tables, tt.wantTables) {
				t.Errorf("tables = %v, want %v", m.Tables, tt.wantTables)
			}
			if m.WriteTarget != tt.wantWrite {
				t.Errorf("write target = %q, want %q", m.WriteTarget, tt.wantWrite)
			}
		})
	}
}

func TestAnalyze_Normalized(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		absent  []string
		present []string
	}{
		{
			name:    "integer literal elided",
			sql:     "SELECT * FROM orders WHERE id = 42",
			absent:  []string{"42"},
			present: []string{"SELECT", "orders"},
		},
		{
			name:    "string literal elided",
			sql:     "SELECT * FROM users WHERE email = 'alice@example.com'",
			absent:  []string{"alice@example.com"},
			present: []string{"users"},
		},
		{
			name:    "in list collapsed",
			sql:     "SELECT * FROM t WHERE x IN (1, 2, 3, 4, 5)",
			absent:  []string{"1, 2, 3, 4, 5"},
			present: []string{"IN"},
		},
		{
			name:    "placeholders survive",
			sql:     "SELECT * FROM a WHERE id = $1",
			present: []string{"$1"},
		},
		{
			name:    "column names are not elided",
			sql:     "UPDATE accounts SET balance = balance - 100 WHERE id = 7",
			absent:  []string{"100"},
			present: []string{"balance", "accounts"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := analyze(tt.sql)
			if m.ParseError {
				t.Fatalf("analyze(%q) failed to parse", tt.sql)
			}
			for _, s := range tt.absent {
				if strings.Contains(m.Normalized, s) {
					t.Errorf("normalized %q still contains %q", m.Normalized, s)
				}
			}
			for _, s := range tt.present {
				if !strings.Contains(m.Normalized, s) {
					t.Errorf("normalized %q is missing %q", m.Normalized, s)
				}
			}
		})
	}
}

func TestAnalyze_FingerprintStableAcrossLiterals(t *testing.T) {
	a := analyze("SELECT * FROM orders WHERE id = 1")
	b := analyze("SELECT * FROM orders WHERE id = 99999")
	c := analyze("SELECT * FROM users WHERE id = 1")

	if a.Fingerprint == "" {
		t.Fatal("fingerprint is empty")
	}
	if a.Fingerprint != b.Fingerprint {
		t.Errorf("same shape produced different fingerprints: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
	if a.Fingerprint == c.Fingerprint {
		t.Errorf("different shapes produced the same fingerprint: %s", a.Fingerprint)
	}
}

// TestAnalyze_ParseFailureKeepsRawStatement documents the deliberate choice
// that an unparseable statement is still reported in full. Losing the text of
// exactly the statements we could not understand would hide both the activity
// and the parser gap.
func TestAnalyze_ParseFailureKeepsRawStatement(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		wantVerb string
	}{
		{"garbage", "this is not sql", "THIS"},
		{"truncated statement", "SELECT * FROM", "SELECT"},
		{"unbalanced paren", "SELECT * FROM t WHERE (a = 1", "SELECT"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := analyze(tt.sql)
			if !m.ParseError {
				t.Fatalf("analyze(%q) unexpectedly parsed", tt.sql)
			}
			if m.Verb != tt.wantVerb {
				t.Errorf("fallback verb = %q, want %q", m.Verb, tt.wantVerb)
			}
			if m.Kind != KindUnknown {
				t.Errorf("kind = %q, want %q", m.Kind, KindUnknown)
			}
			if m.Normalized != "" {
				t.Errorf("normalized should be empty on parse failure, got %q", m.Normalized)
			}
			// The raw text is supplied by the caller from the statement it
			// already holds; Analyze's job is to flag the failure so the
			// caller knows to fall back. StatementText covers that contract.
			if got := StatementText(m, tt.sql, LevelMetadata); got != tt.sql {
				t.Errorf("StatementText at metadata = %q, want the raw statement %q", got, tt.sql)
			}
		})
	}
}

func TestStatementText(t *testing.T) {
	const raw = "SELECT * FROM orders WHERE id = 42"
	parsed := analyze(raw)

	tests := []struct {
		name  string
		level Level
		meta  SQLMeta
		sql   string
		want  string
	}{
		{"off emits nothing", LevelOff, parsed, raw, ""},
		{"metadata omits text", LevelMetadata, parsed, raw, ""},
		{"normalized elides constants", LevelNormalized, parsed, raw, parsed.Normalized},
		{"full is verbatim", LevelFull, parsed, raw, raw},
		{"parse failure falls back to raw at metadata", LevelMetadata, SQLMeta{ParseError: true}, raw, raw},
		{"parse failure falls back to raw at normalized", LevelNormalized, SQLMeta{ParseError: true}, raw, raw},
		{"parse failure stays quiet at off", LevelOff, SQLMeta{ParseError: true}, raw, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StatementText(tt.meta, tt.sql, tt.level); got != tt.want {
				t.Errorf("StatementText = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAnalyze_CacheHit(t *testing.T) {
	const sql = "SELECT * FROM cache_probe WHERE id = 1"
	first := Analyze(sql)
	second := Analyze(sql)

	if first.Fingerprint != second.Fingerprint {
		t.Errorf("cached analysis differs: %q vs %q", first.Fingerprint, second.Fingerprint)
	}
	if _, ok := analysisCache.get(sql); !ok {
		t.Error("statement was not memoized")
	}
}

func TestMetaCache_EvictsOldest(t *testing.T) {
	c := newMetaCache(2)
	c.put("a", SQLMeta{Verb: "A"})
	c.put("b", SQLMeta{Verb: "B"})
	// Touch "a" so "b" becomes the least recently used.
	if _, ok := c.get("a"); !ok {
		t.Fatal("a should still be cached")
	}
	c.put("c", SQLMeta{Verb: "C"})

	if c.len() != 2 {
		t.Errorf("cache holds %d entries, want 2", c.len())
	}
	if _, ok := c.get("b"); ok {
		t.Error("b should have been evicted as least recently used")
	}
	if _, ok := c.get("a"); !ok {
		t.Error("a should have been retained")
	}
}

func TestMetaCache_SkipsOversizedStatements(t *testing.T) {
	c := newMetaCache(4)
	huge := strings.Repeat("x", maxCacheableStatement+1)
	c.put(huge, SQLMeta{Verb: "SELECT"})

	if c.len() != 0 {
		t.Errorf("oversized statement was cached; cache holds %d entries", c.len())
	}
}
