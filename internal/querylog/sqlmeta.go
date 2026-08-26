package querylog

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/parser"
	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/sem/tree"
)

// Statement kinds reported in the "kind" log field.
const (
	KindRead    = "dml_read"
	KindWrite   = "dml_write"
	KindDDL     = "ddl"
	KindDCL     = "dcl"
	KindTCL     = "tcl"
	KindUtility = "utility"
	KindUnknown = "unknown"
)

// SQLMeta is the result of analyzing one SQL statement.
type SQLMeta struct {
	// Verb is the statement tag: "SELECT", "INSERT", "CREATE TABLE".
	// On a parse failure it falls back to the leading token, upper-cased.
	Verb string

	// Kind is one of the Kind* constants above.
	Kind string

	// Tables lists every relation the statement references, as written in
	// the statement. Unqualified names stay unqualified: waypoint does not
	// know the session's search_path, so inventing a "public." prefix would
	// be a guess rather than a fact. Sorted and deduplicated.
	Tables []string

	// WriteTarget is the relation an INSERT/UPDATE/DELETE/TRUNCATE mutates,
	// empty for reads and for statements with no single target.
	WriteTarget string

	// Normalized is the statement rendered with constants elided. Empty when
	// the statement could not be parsed.
	Normalized string

	// Fingerprint is a stable short hash over Normalized, so identical
	// statement shapes group together across connections and instances.
	// Empty when the statement could not be parsed.
	Fingerprint string

	// ParseError reports that the parser rejected the statement. Callers
	// must log the raw statement text in this case — see Analyze.
	ParseError bool
}

// Analyze parses sql and extracts its shape.
//
// On success the caller gets the normalized text and full metadata. On a parse
// failure the caller gets ParseError plus a best-effort Verb, and is expected
// to log the raw statement verbatim at every level above LevelOff — including
// LevelMetadata, which otherwise carries no statement text. Dropping the text
// of exactly the statements we failed to understand would hide both the
// activity being audited and the parser gap that hid it.
//
// Results are memoized; see the package-level cache.
func Analyze(sql string) SQLMeta {
	if m, ok := analysisCache.get(sql); ok {
		return m
	}
	m := analyze(sql)
	analysisCache.put(sql, m)
	return m
}

func analyze(sql string) SQLMeta {
	parsed, err := parser.ParseOne(sql)
	if err != nil {
		return SQLMeta{
			Verb:       leadingToken(sql),
			Kind:       KindUnknown,
			ParseError: true,
		}
	}

	ast := parsed.AST
	m := SQLMeta{
		Verb: strings.ToUpper(ast.StatementTag()),
		Kind: classify(ast),
	}

	// Render with constants elided, collecting every table name the
	// formatter walks past. Using the formatter's own traversal means we
	// inherit its coverage of every statement type the grammar accepts,
	// rather than maintaining a parallel walker that silently misses nodes.
	var tables []string
	collect := func(ctx *tree.FmtCtx, tn *tree.TableName) {
		tables = append(tables, tn.String())
		// Clear the hook while rendering so TableName.Format takes its
		// normal path instead of re-entering this callback.
		ctx.WithReformatTableNames(nil, func() { ctx.FormatNode(tn) })
	}
	fmtCtx := tree.NewFmtCtx(tree.FmtHideConstants, tree.FmtReformatTableNames(collect))
	fmtCtx.FormatNode(ast)
	m.Normalized = fmtCtx.CloseAndGetString()

	sum := sha256.Sum256([]byte(m.Normalized))
	m.Fingerprint = hex.EncodeToString(sum[:8])

	m.Tables = dedupeTables(tables, cteNames(ast))
	m.WriteTarget = writeTarget(ast)

	return m
}

// classify maps a statement to one of the Kind* constants. CockroachDB's own
// StatementType covers DDL/DCL/TCL; within DML we split reads from writes,
// since "did this user modify data" is the question an audit log exists to
// answer.
func classify(ast tree.Statement) string {
	switch ast.(type) {
	case *tree.Insert, *tree.Update, *tree.Delete, *tree.Truncate:
		return KindWrite
	case *tree.Select, *tree.ParenSelect, *tree.SelectClause, *tree.ValuesClause:
		return KindRead
	}

	switch ast.StatementType() {
	case tree.TypeDDL:
		return KindDDL
	case tree.TypeDCL:
		return KindDCL
	case tree.TypeTCL:
		return KindTCL
	case tree.TypeDML:
		// DML that is not one of the mutation statements handled above:
		// SET, SHOW, COPY, EXPLAIN over a mutation, and so on. The return
		// type separates them: row-returning statements are reads, statements
		// that only acknowledge (SET, SHOW ... session state) are utilities,
		// and anything reporting affected rows is a write. Erring toward
		// KindWrite for the remainder flags mutations rather than hiding them.
		switch ast.StatementReturnType() {
		case tree.Rows:
			return KindRead
		case tree.Ack:
			return KindUtility
		default:
			return KindWrite
		}
	default:
		return KindUtility
	}
}

// writeTarget returns the relation a mutation targets, if there is exactly one.
func writeTarget(ast tree.Statement) string {
	switch stmt := ast.(type) {
	case *tree.Insert:
		return tableExprName(stmt.Table)
	case *tree.Update:
		return tableExprName(stmt.Table)
	case *tree.Delete:
		return tableExprName(stmt.Table)
	case *tree.Truncate:
		if len(stmt.Tables) == 1 {
			return stmt.Tables[0].String()
		}
	}
	return ""
}

func tableExprName(te tree.TableExpr) string {
	switch t := te.(type) {
	case *tree.TableName:
		return t.String()
	case *tree.AliasedTableExpr:
		return tableExprName(t.Expr)
	case *tree.ParenTableExpr:
		return tableExprName(t.Expr)
	}
	return ""
}

// cteNames collects the aliases bound by a WITH clause. They look like tables
// in the FROM clause but are not relations, so they are excluded from Tables.
func cteNames(ast tree.Statement) map[string]struct{} {
	names := map[string]struct{}{}

	var with *tree.With
	switch stmt := ast.(type) {
	case *tree.Select:
		with = stmt.With
	case *tree.Insert:
		with = stmt.With
	case *tree.Update:
		with = stmt.With
	case *tree.Delete:
		with = stmt.With
	}
	if with == nil {
		return names
	}
	for _, cte := range with.CTEList {
		if cte == nil {
			continue
		}
		names[strings.ToLower(string(cte.Name.Alias))] = struct{}{}
	}
	return names
}

func dedupeTables(tables []string, exclude map[string]struct{}) []string {
	if len(tables) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tables))
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		if t == "" {
			continue
		}
		if _, skip := exclude[strings.ToLower(t)]; skip {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// leadingToken returns the first word of a statement, upper-cased. It is the
// fallback verb for statements the parser rejects — crude, but enough to tell
// a failed SELECT from a failed DROP when triaging.
func leadingToken(sql string) string {
	s := strings.TrimLeft(sql, " \t\r\n(")
	end := strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '(' || r == ';'
	})
	if end >= 0 {
		s = s[:end]
	}
	if s == "" {
		return ""
	}
	return strings.ToUpper(s)
}

// StatementText decides what statement text, if any, a record at the given
// level should carry.
//
// The policy in one place, because getting it wrong leaks row data:
//
//   - LevelOff        — nothing, ever.
//   - LevelMetadata   — nothing, unless the parser rejected the statement.
//   - LevelNormalized — constants elided, or the raw text on a parse failure.
//   - LevelFull       — the statement exactly as the client sent it.
//
// The parse-failure fallback is deliberate: a statement we could not parse is
// the one most worth seeing, so it is reported verbatim even at LevelMetadata.
// The consequence is that no level except LevelOff is a hard guarantee against
// literals reaching the logs, which the documentation states plainly.
func StatementText(m SQLMeta, raw string, level Level) string {
	if level <= LevelOff {
		return ""
	}
	if level >= LevelFull {
		return raw
	}
	if m.ParseError {
		return raw
	}
	if level >= LevelNormalized {
		return m.Normalized
	}
	return ""
}
