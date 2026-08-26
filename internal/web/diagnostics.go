package web

import (
	"context"
	"strings"

	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/parser"
	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/sem/tree"
	"github.com/cockroachdb/errors"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/redoapp/waypoint/internal/querylog"
)

// Editor diagnostics.
//
// These are advisory only. The provisioned role is the security boundary and
// Postgres is what actually refuses a statement; if the linter and the
// database ever disagree, the database is right. Nothing here runs on the
// execution path, so a bug in it cannot become an authorization decision in
// either direction.

// Diagnostic is one editor annotation, in CodeMirror's lint shape.
type Diagnostic struct {
	From     int    `json:"from"`
	To       int    `json:"to"`
	Severity string `json:"severity"` // "error" | "warning" | "info"
	Message  string `json:"message"`
	Source   string `json:"source,omitempty"`
}

// diagnose returns syntax errors and permission warnings for the buffer.
func (s *Server) diagnose(ctx context.Context, pool *pgxpool.Pool, cacheKey, sql string) []Diagnostic {
	out := []Diagnostic{}
	cat, err := s.catalog.Get(ctx, cacheKey, pool)
	if err != nil {
		cat = &Catalog{}
	}

	for _, span := range splitStatements(sql) {
		text := strings.TrimSuffix(strings.TrimSpace(span.Text), ";")
		if text == "" {
			continue
		}

		stmt, perr := parser.ParseOne(text)
		if perr != nil {
			from, to := parseErrorRange(text, perr, span.Start)
			out = append(out, Diagnostic{
				From:     from,
				To:       to,
				Severity: "error",
				Message:  cleanParseError(perr),
				Source:   "syntax",
			})
			continue
		}

		out = append(out, permissionDiagnostics(cat, text, span)...)
		out = append(out, shapeDiagnostics(stmt.AST, span)...)
	}
	return out
}

// permissionDiagnostics warns when the statement needs a privilege the user
// does not hold on a specific relation.
//
// The privilege facts come from has_table_privilege, which resolves through
// the group memberships provision uses to implement presets. That is why the
// message can name the table and the missing privilege rather than saying
// "your grant is read-only".
func permissionDiagnostics(cat *Catalog, text string, span stmtSpan) []Diagnostic {
	meta := querylog.Analyze(text)
	if meta.ParseError {
		return nil
	}

	var out []Diagnostic
	need := requiredPrivilege(meta.Verb)

	check := func(name string, priv string) {
		schema, bare := splitQualified(name)
		t, ok := cat.lookup(schema, bare)
		if !ok {
			return
		}
		if hasPrivilege(t, priv) {
			return
		}
		from, to := locateIdentifier(text, bare, span.Start)
		out = append(out, Diagnostic{
			From:     from,
			To:       to,
			Severity: "warning",
			Message:  "you do not have " + priv + " on " + t.Qualified(),
			Source:   "permission",
		})
	}

	if need != "" && meta.WriteTarget != "" {
		check(meta.WriteTarget, need)
	}

	// Reads need SELECT on everything referenced, writes included.
	for _, tbl := range meta.Tables {
		if meta.WriteTarget != "" && strings.EqualFold(tbl, meta.WriteTarget) && need != "INSERT" {
			// An UPDATE/DELETE target is read as well as written.
			check(tbl, "SELECT")
			continue
		}
		if meta.WriteTarget != "" && strings.EqualFold(tbl, meta.WriteTarget) {
			continue
		}
		check(tbl, "SELECT")
	}

	if meta.Kind == querylog.KindDDL {
		out = append(out, Diagnostic{
			From:     span.Start,
			To:       span.Start + len(text),
			Severity: "info",
			Message:  "DDL requires the admin preset; Postgres will reject it otherwise",
			Source:   "permission",
		})
	}
	return out
}

// shapeDiagnostics flags statements whose shape is usually a mistake — an
// unqualified UPDATE or DELETE being the classic one.
func shapeDiagnostics(ast tree.Statement, span stmtSpan) []Diagnostic {
	var out []Diagnostic
	switch t := ast.(type) {
	case *tree.Update:
		if t.Where == nil {
			out = append(out, Diagnostic{
				From: span.Start, To: span.End,
				Severity: "warning",
				Message:  "UPDATE without a WHERE clause affects every row",
				Source:   "shape",
			})
		}
	case *tree.Delete:
		if t.Where == nil {
			out = append(out, Diagnostic{
				From: span.Start, To: span.End,
				Severity: "warning",
				Message:  "DELETE without a WHERE clause removes every row",
				Source:   "shape",
			})
		}
	}
	return out
}

func requiredPrivilege(verb string) string {
	switch strings.ToUpper(verb) {
	case "INSERT":
		return "INSERT"
	case "UPDATE":
		return "UPDATE"
	case "DELETE", "TRUNCATE":
		return "DELETE"
	}
	return ""
}

func hasPrivilege(t TableInfo, priv string) bool {
	switch priv {
	case "SELECT":
		return t.Select
	case "INSERT":
		return t.Insert
	case "UPDATE":
		return t.Update
	case "DELETE":
		return t.Delete
	}
	return true
}

func splitQualified(name string) (string, string) {
	name = strings.Trim(name, `"`)
	if i := strings.LastIndex(name, "."); i >= 0 {
		return strings.Trim(name[:i], `"`), strings.Trim(name[i+1:], `"`)
	}
	return "", name
}

// locateIdentifier finds where an identifier appears in the statement so the
// annotation lands on the table name rather than the whole statement.
func locateIdentifier(text, ident string, base int) (int, int) {
	lower := strings.ToLower(text)
	target := strings.ToLower(ident)
	for _, tok := range tokenize(text) {
		if tok.Kind != tokWord {
			continue
		}
		if strings.ToLower(unquoteIdent(tok.Text)) == target {
			return base + tok.Start, base + tok.End
		}
	}
	if i := strings.Index(lower, target); i >= 0 {
		return base + i, base + i + len(ident)
	}
	return base, base + len(text)
}

// parseErrorRange maps a parser error onto a range in the buffer. The parser
// reports position as a caret line in the error's detail, so the caret column
// is read back out and mapped to a byte offset.
func parseErrorRange(text string, err error, base int) (int, int) {
	detail := errors.FlattenDetails(err)
	lines := strings.Split(detail, "\n")
	for i, ln := range lines {
		if !strings.HasPrefix(strings.TrimSpace(ln), "source SQL:") {
			continue
		}
		if i+2 >= len(lines) {
			break
		}
		srcLine := lines[i+1]
		caretLine := lines[i+2]
		col := strings.Index(caretLine, "^")
		if col < 0 {
			break
		}
		// Locate the reported line within the statement, then offset into it.
		lineStart := strings.Index(text, srcLine)
		if lineStart < 0 {
			lineStart = 0
		}
		if col > len(srcLine) {
			col = len(srcLine)
		}
		start := base + lineStart + col
		end := start + 1
		// Extend across the offending word so the squiggle is visible.
		for _, tok := range tokenize(text) {
			if base+tok.Start <= start && start < base+tok.End {
				return base + tok.Start, base + tok.End
			}
		}
		return start, end
	}
	return base, base + len(text)
}

// cleanParseError strips the caret block, which the editor renders itself.
func cleanParseError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "\nsource SQL:"); i >= 0 {
		msg = msg[:i]
	}
	return strings.TrimSpace(msg)
}
