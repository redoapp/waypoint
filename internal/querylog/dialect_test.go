package querylog

import (
	"strings"
	"testing"
)

// postgresCorpus is a sample of real-world PostgreSQL syntax. Waypoint parses
// with the CockroachDB grammar — the same parser it already uses to validate
// ACL-supplied SQL — which covers most but not all of PostgreSQL.
//
// This matters beyond metadata quality: a statement that fails to parse is
// logged with its raw text at every level, so the size and shape of this gap
// is the real bound on how much literal content can reach the logs.
var postgresCorpus = []string{
	"INSERT INTO t (a,b) VALUES (1,2) ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b",
	"INSERT INTO t VALUES (1) RETURNING id, created_at",
	"SELECT DISTINCT ON (user_id) * FROM events ORDER BY user_id, ts DESC",
	"SELECT * FROM t WHERE data->>'name' = 'x'",
	"SELECT * FROM t WHERE data @> '{\"a\":1}'::jsonb",
	"SELECT * FROM t WHERE tags && ARRAY['a','b']",
	"SELECT * FROM t WHERE name ILIKE '%foo%'",
	"SELECT row_number() OVER (PARTITION BY a ORDER BY b) FROM t",
	"SELECT * FROM generate_series(1,10) AS g(i)",
	"SELECT * FROM t, LATERAL (SELECT * FROM u WHERE u.id = t.id) s",
	"SELECT * FROM t FOR UPDATE SKIP LOCKED",
	"SELECT EXTRACT(EPOCH FROM now())",
	"SELECT a::text, b::int8 FROM t",
	"WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM r WHERE n < 5) SELECT * FROM r",
	"UPDATE t SET (a,b) = (1,2) WHERE id = 3",
	"DELETE FROM t USING u WHERE t.id = u.id",
	"CREATE INDEX CONCURRENTLY idx ON t (a) WHERE b IS NOT NULL",
	"CREATE TABLE t (id serial PRIMARY KEY, data jsonb NOT NULL DEFAULT '{}')",
	"ALTER TABLE t ALTER COLUMN a TYPE bigint USING a::bigint",
	"COPY t (a,b) FROM STDIN WITH (FORMAT csv)",
	"SELECT string_agg(a, ',' ORDER BY b) FROM t",
	"SELECT * FROM t WHERE id = ANY($1)",
	"SELECT COALESCE(a, b, 'x') FROM t",
	"SELECT * FROM t OFFSET 10 LIMIT 5",
	"SELECT * FROM ONLY parent",
	"SET LOCAL statement_timeout = '5s'",
	"SHOW search_path",
	"BEGIN ISOLATION LEVEL SERIALIZABLE",
	"SELECT pg_advisory_lock(1)",
	"SELECT * FROM information_schema.tables",
	"SELECT nextval('seq')",
	"CREATE MATERIALIZED VIEW mv AS SELECT * FROM t",
	"REFRESH MATERIALIZED VIEW CONCURRENTLY mv",
	"SELECT CASE WHEN a > 1 THEN 'x' ELSE 'y' END FROM t",
	"SELECT array_agg(DISTINCT a) FILTER (WHERE b > 0) FROM t",
	"SELECT * FROM t ORDER BY a NULLS LAST",
	"PREPARE p (int) AS SELECT * FROM t WHERE id = $1",
	"DEALLOCATE p",
	"SELECT to_tsvector('english', body) @@ to_tsquery('cat') FROM docs",
	"SELECT * FROM t WHERE ts BETWEEN SYMMETRIC '2020-01-01' AND '2021-01-01'",
}

// knownUnsupported records PostgreSQL syntax the CockroachDB grammar rejects.
// These are logged with raw text rather than dropped, which is the documented
// behavior — this list exists so the gap stays visible and so a parser upgrade
// that fixes one shows up as a failing test rather than passing unnoticed.
var knownUnsupported = []string{
	"SELECT * FROM t TABLESAMPLE SYSTEM (10)",
	"EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM t",
	"SELECT * FROM t GROUP BY GROUPING SETS ((a),(b))",
	"LISTEN chan",
	"VACUUM ANALYZE t",
}

func TestAnalyze_PostgresCorpusParses(t *testing.T) {
	for _, sql := range postgresCorpus {
		t.Run(truncateName(sql), func(t *testing.T) {
			m := analyze(sql)
			if m.ParseError {
				t.Errorf("failed to parse, so this statement would be logged with raw text:\n  %s", sql)
			}
			if m.Verb == "" {
				t.Errorf("no verb extracted from: %s", sql)
			}
		})
	}
}

// The documented contract for a statement the parser rejects: flagged, given a
// best-effort verb, and reported with its raw text rather than dropped.
func TestAnalyze_KnownUnsupportedDegradesGracefully(t *testing.T) {
	for _, sql := range knownUnsupported {
		t.Run(truncateName(sql), func(t *testing.T) {
			m := analyze(sql)
			if !m.ParseError {
				t.Errorf("now parses — move it out of knownUnsupported: %s", sql)
			}
			if m.Verb == "" {
				t.Errorf("no fallback verb for: %s", sql)
			}
			if got := StatementText(m, sql, LevelMetadata); got != sql {
				t.Errorf("raw statement not preserved: got %q, want %q", got, sql)
			}
		})
	}
}

// A guard on the overall gap. It is not a precise measurement of production
// traffic, but it stops a parser change from silently widening the set of
// statements that get logged verbatim.
func TestAnalyze_ParseFailureRateStaysBounded(t *testing.T) {
	all := append(append([]string{}, postgresCorpus...), knownUnsupported...)

	var failed int
	for _, sql := range all {
		if analyze(sql).ParseError {
			failed++
		}
	}

	rate := 100 * float64(failed) / float64(len(all))
	t.Logf("%d/%d statements unparseable (%.1f%%)", failed, len(all), rate)

	if failed != len(knownUnsupported) {
		t.Errorf("%d statements failed to parse, expected exactly the %d known-unsupported ones",
			failed, len(knownUnsupported))
	}
}

func truncateName(sql string) string {
	name := strings.Join(strings.Fields(sql), " ")
	if len(name) > 48 {
		name = name[:48]
	}
	return name
}
