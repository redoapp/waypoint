package web

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Completion is one suggestion, shaped for CodeMirror's autocomplete.
//
// Apply carries snippet syntax when the completion inserts more than a plain
// identifier — a JOIN completion inserts the relation, an alias tab stop, and
// the full ON predicate derived from the foreign key.
//
// Section and SectionRank carry the semantic tier. They matter more than Boost
// does: see the note on sections below.
type Completion struct {
	Label string `json:"label"`
	// DisplayLabel is shown in the popup when it differs from Label.
	//
	// Both layers match on Label, never on DisplayLabel, and CodeMirror only
	// matches a single-character query against position 0 of the label. So a
	// column carrying its qualifier in Label — "c.email" — could never be
	// reached by typing "e". Label therefore stays the bare column name and
	// the qualified form lives here and in Apply.
	DisplayLabel string  `json:"displayLabel,omitempty"`
	Detail       string  `json:"detail,omitempty"`
	Type         string  `json:"type,omitempty"`
	Info         string  `json:"info,omitempty"`
	Apply        string  `json:"apply,omitempty"`
	Boost        float64 `json:"boost,omitempty"`
	Section      string  `json:"section,omitempty"`
	SectionRank  int     `json:"sectionRank,omitempty"`
}

// Ranking.
//
// CodeMirror scores each option by how well it matches what has been typed,
// using penalties in the hundreds — a match that is not at the start of the
// word costs 700, a gapped match 1100 — and then adds the option's boost,
// which it documents as a -99..99 nudge. Boost alone therefore cannot express
// "a column of a table in this query outranks an unrelated relation": match
// quality drowns it out, which is why suggestions came back in a sensible-
// looking but semantically wrong order.
//
// Sections are the mechanism that does express it. CodeMirror offsets every
// option's score by -1e5 per section rank, which dwarfs both the match
// penalties and boost, so section order is absolute and match quality only
// orders options *within* a tier. Boost is still useful, but only for
// arranging peers inside one section.
const (
	sectionStatements = "statements"
	sectionColumns    = "columns"
	sectionJoins      = "joins"
	sectionTables     = "tables"
	sectionKeywords   = "keywords"
)

const (
	rankStatements = 1
	rankColumns    = 1
	rankJoins      = 2
	rankTables     = 3
	rankKeywords   = 4
)

// Within-section nudges, in CodeMirror's -99..99 boost range.
const (
	boostJoinColumn = 60 // the column a foreign key actually joins on
	boostDirectJoin = 60 // reachable in one hop
	boostAdjacent   = 30 // FK-related to something already in the statement
	boostCommon     = 40 // a statement verb people reach for most
)

// CompletionResult mirrors CodeMirror's CompletionResult.
type CompletionResult struct {
	From    int          `json:"from"`
	Options []Completion `json:"options"`
}

const maxCompletions = 200

// statementVerbs is what belongs at the start of a statement. Offering
// relation names here was the wrong answer: nothing can follow a bare table
// name at position zero.
var statementVerbs = []struct {
	Label string
	Boost float64
}{
	// Distinct boosts, not one shared value: options that tie fall back to
	// alphabetical order, which would put DELETE FROM above SELECT.
	{"SELECT", boostCommon},
	{"WITH", boostCommon - 5},
	{"INSERT INTO", boostCommon - 10},
	{"UPDATE", boostCommon - 12},
	{"DELETE FROM", boostCommon - 14},
	{"EXPLAIN", boostCommon - 25},
	{"EXPLAIN ANALYZE", boostCommon - 26},
	{"CREATE TABLE", 0},
	{"ALTER TABLE", 0},
	{"DROP TABLE", 0},
	{"TRUNCATE", 0},
	{"BEGIN", 0},
	{"COMMIT", 0},
	{"ROLLBACK", 0},
	{"SET", 0},
	{"SHOW", 0},
}

var sqlKeywords = []string{
	"SELECT", "FROM", "WHERE", "GROUP BY", "ORDER BY", "HAVING", "LIMIT",
	"OFFSET", "JOIN", "LEFT JOIN", "RIGHT JOIN", "INNER JOIN", "FULL JOIN",
	"CROSS JOIN", "ON", "USING", "AS", "AND", "OR", "NOT", "IN", "EXISTS",
	"BETWEEN", "LIKE", "ILIKE", "IS NULL", "IS NOT NULL", "INSERT INTO",
	"VALUES", "UPDATE", "SET", "DELETE FROM", "RETURNING", "WITH", "UNION",
	"UNION ALL", "INTERSECT", "EXCEPT", "DISTINCT", "CASE", "WHEN", "THEN",
	"ELSE", "END", "COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE", "NULLIF",
	"CAST", "EXTRACT", "NOW", "ASC", "DESC",
}

// complete produces suggestions for the caret. The catalog it reads was
// introspected on the user's own role, so nothing here can suggest an object
// the user is not allowed to see.
func (s *Server) complete(ctx context.Context, pool *pgxpool.Pool, cacheKey, sql string, pos int) (*CompletionResult, error) {
	cat, err := s.catalog.Get(ctx, cacheKey, pool)
	if err != nil {
		return nil, err
	}

	cc := analyzeCaret(sql, pos)
	res := &CompletionResult{From: cc.From, Options: []Completion{}}
	prefix := strings.ToLower(cc.Prefix)

	switch cc.Kind {
	case kindStatementStart:
		res.Options = completeStatementStart()

	case kindColumnOf:
		res.Options = s.completeQualified(ctx, pool, cacheKey, cat, cc)

	case kindJoinTarget:
		res.Options = s.completeJoinTargets(cat, cc)

	case kindTable:
		res.Options = completeTables(cat, cc, "")

	default:
		// Expression position: in-scope columns first, then relations, then
		// keywords. Columns of the tables already named in the statement are
		// what the user wants the overwhelming majority of the time.
		res.Options = s.completeExpression(ctx, pool, cacheKey, cat, cc)
	}

	res.Options = filterAndRank(res.Options, prefix)
	res.Options = collapseSingleSection(res.Options)
	return res, nil
}

func completeStatementStart() []Completion {
	out := make([]Completion, 0, len(statementVerbs))
	for _, v := range statementVerbs {
		out = append(out, Completion{
			Label:       v.Label,
			Type:        "keyword",
			Boost:       v.Boost,
			Section:     sectionStatements,
			SectionRank: rankStatements,
		})
	}
	return out
}

// collapseSingleSection drops section labels when every option shares one, so
// a popup that is entirely columns does not carry a redundant header.
func collapseSingleSection(opts []Completion) []Completion {
	if len(opts) == 0 {
		return opts
	}
	first := opts[0].Section
	for _, o := range opts {
		if o.Section != first {
			return opts
		}
	}
	for i := range opts {
		opts[i].Section = ""
		opts[i].SectionRank = 0
	}
	return opts
}

// completeQualified handles "alias." and "schema." positions.
func (s *Server) completeQualified(ctx context.Context, pool *pgxpool.Pool, cacheKey string, cat *Catalog, cc caretContext) []Completion {
	// Alias or table name in scope?
	if ref, ok := resolveRef(cat, cc.Tables, cc.Qualifier); ok {
		cols, err := s.catalog.Columns(ctx, cacheKey, pool, ref.Schema, ref.Name)
		if err != nil {
			return nil
		}
		out := make([]Completion, 0, len(cols))
		for _, c := range cols {
			// Already qualified by what the user typed before the dot.
			out = append(out, columnCompletion(c, ref, ""))
		}
		// Inside an ON predicate, lead with the columns the foreign key says
		// actually join these relations.
		if cc.AfterOn {
			boostJoinColumns(out, cat, cc, ref)
		}
		return out
	}

	// Schema qualifier: offer its relations.
	var out []Completion
	for _, t := range cat.Tables {
		if !strings.EqualFold(t.Schema, cc.Qualifier) {
			continue
		}
		out = append(out, tableCompletion(t, t.Name, 0))
	}
	return out
}

// completeExpression offers columns from every relation in scope, plus
// relations and keywords.
func (s *Server) completeExpression(ctx context.Context, pool *pgxpool.Pool, cacheKey string, cat *Catalog, cc caretContext) []Completion {
	var out []Completion
	qualify := len(cc.Tables) > 1

	for _, ref := range cc.Tables {
		handle := refHandle(ref)
		resolved, ok := resolveRef(cat, cc.Tables, handle)
		if !ok {
			continue
		}
		cols, err := s.catalog.Columns(ctx, cacheKey, pool, resolved.Schema, resolved.Name)
		if err != nil {
			continue
		}
		// Qualify with the handle the statement actually binds — the alias
		// when there is one. Postgres rejects the original table name once a
		// relation is aliased ("invalid reference to FROM-clause entry"), so
		// completing "orders.id" for "FROM orders o" inserts broken SQL.
		qualifier := ""
		if qualify {
			qualifier = handle
		}
		for _, c := range cols {
			out = append(out, columnCompletion(c, resolved, qualifier))
		}
	}

	for _, t := range cat.Tables {
		out = append(out, tableCompletion(t, t.Name, -1))
	}
	for _, kw := range sqlKeywords {
		out = append(out, Completion{
			Label:       kw,
			Type:        "keyword",
			Section:     sectionKeywords,
			SectionRank: rankKeywords,
		})
	}
	return out
}

// completeTables offers relation names, boosting those the FK graph says are
// related to what is already in the statement.
func completeTables(cat *Catalog, cc caretContext, _ string) []Completion {
	adjacent := adjacentTables(cat, cc.Tables)
	out := make([]Completion, 0, len(cat.Tables))
	for _, t := range cat.Tables {
		boost := 0.0
		if adjacent[strings.ToLower(t.Qualified())] {
			boost = boostAdjacent
		}
		out = append(out, tableCompletion(t, t.Name, boost))
	}
	return out
}

// completeJoinTargets is the join assistant. For every relation reachable from
// what is already in the statement, it emits a completion that inserts the
// relation, a linked alias tab stop, and the ON predicate the foreign keys
// imply — including multi-hop paths, which insert every intermediate join.
func (s *Server) completeJoinTargets(cat *Catalog, cc caretContext) []Completion {
	var out []Completion
	used := usedAliases(cc.Tables)
	seen := map[string]bool{}

	if len(cc.Tables) > 0 {
		for _, path := range joinPaths(cat, cc.Tables, 3) {
			key := strings.ToLower(path.target.Qualified())
			if seen[key] {
				continue
			}
			seen[key] = true
			apply, detail := renderJoinPath(path, used)
			// Fewer hops first, but all join paths outrank plain relations
			// because they carry a ready-made ON clause.
			boost := boostDirectJoin - float64(20*(len(path.steps)-1))
			out = append(out, Completion{
				Label:       path.target.Name,
				Detail:      detail,
				Type:        path.target.Kind,
				Info:        fmt.Sprintf("%s — %s", path.target.Qualified(), detail),
				Apply:       apply,
				Boost:       boost,
				Section:     sectionJoins,
				SectionRank: rankJoins,
			})
		}
	}

	// Everything else stays reachable, just ranked below the FK-derived
	// suggestions. Filtering unrelated tables out would be worse than
	// ranking them down: schemas are not always modelled with real FKs.
	for _, t := range cat.Tables {
		if seen[strings.ToLower(t.Qualified())] {
			continue
		}
		out = append(out, tableCompletion(t, t.Name, -1))
	}
	return out
}

// joinPath is a chain of joins from the statement's existing relations to a
// target relation.
type joinPath struct {
	target TableInfo
	steps  []joinStep
}

type joinStep struct {
	// from is the alias (or name) of the relation on the left of this join.
	from     string
	table    TableInfo
	srcCols  []string
	tgtCols  []string
	reversed bool
}

// joinPaths runs a breadth-first search over the FK graph from every relation
// already in the statement, returning the shortest path to each reachable
// relation up to maxHops.
func joinPaths(cat *Catalog, inScope []tableRef, maxHops int) []joinPath {
	type node struct {
		table  TableInfo
		handle string
		steps  []joinStep
	}

	var queue []node
	visited := map[string]bool{}

	for _, ref := range inScope {
		t, ok := cat.lookup(ref.Schema, ref.Name)
		if !ok {
			continue
		}
		key := strings.ToLower(t.Qualified())
		visited[key] = true
		queue = append(queue, node{table: t, handle: refHandle(ref)})
	}

	var paths []joinPath
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if len(cur.steps) >= maxHops {
			continue
		}
		for _, fk := range cat.fksFor(cur.table.Schema, cur.table.Name) {
			var next TableInfo
			var srcCols, tgtCols []string
			reversed := false

			if strings.EqualFold(fk.SrcTable, cur.table.Name) && strings.EqualFold(fk.SrcSchema, cur.table.Schema) {
				t, ok := cat.lookup(fk.TgtSchema, fk.TgtTable)
				if !ok {
					continue
				}
				next, srcCols, tgtCols = t, fk.SrcCols, fk.TgtCols
			} else {
				t, ok := cat.lookup(fk.SrcSchema, fk.SrcTable)
				if !ok {
					continue
				}
				next, srcCols, tgtCols, reversed = t, fk.TgtCols, fk.SrcCols, true
			}

			key := strings.ToLower(next.Qualified())
			if visited[key] {
				continue
			}
			visited[key] = true

			step := joinStep{
				from:     cur.handle,
				table:    next,
				srcCols:  srcCols,
				tgtCols:  tgtCols,
				reversed: reversed,
			}
			steps := append(append([]joinStep{}, cur.steps...), step)
			paths = append(paths, joinPath{target: next, steps: steps})
			queue = append(queue, node{table: next, handle: "", steps: steps})
		}
	}

	sort.SliceStable(paths, func(i, j int) bool {
		if len(paths[i].steps) != len(paths[j].steps) {
			return len(paths[i].steps) < len(paths[j].steps)
		}
		return paths[i].target.Qualified() < paths[j].target.Qualified()
	})
	return paths
}

// renderJoinPath turns a path into snippet text. The alias of the final
// relation is a linked tab stop so the user can rename it in one keystroke,
// and composite foreign keys emit one AND-ed predicate per column pair.
func renderJoinPath(p joinPath, used map[string]bool) (string, string) {
	local := map[string]bool{}
	for k := range used {
		local[k] = true
	}

	var b strings.Builder
	handles := map[int]string{}
	for i, st := range p.steps {
		alias := generateAlias(st.table.Name, local)
		local[strings.ToLower(alias)] = true
		handles[i] = alias

		from := st.from
		if from == "" && i > 0 {
			from = handles[i-1]
		}

		if i > 0 {
			b.WriteString("\n  JOIN ")
		}
		if i == len(p.steps)-1 {
			// Final relation: alias is a linked snippet placeholder.
			fmt.Fprintf(&b, "%s ${%s} ON ", qualifiedRef(st.table), alias)
		} else {
			fmt.Fprintf(&b, "%s %s ON ", qualifiedRef(st.table), alias)
		}

		aliasRef := alias
		if i == len(p.steps)-1 {
			aliasRef = "${" + alias + "}"
		}
		for j := range st.srcCols {
			if j > 0 {
				b.WriteString(" AND ")
			}
			if j >= len(st.tgtCols) {
				break
			}
			if st.reversed {
				fmt.Fprintf(&b, "%s.%s = %s.%s", from, st.srcCols[j], aliasRef, st.tgtCols[j])
			} else {
				fmt.Fprintf(&b, "%s.%s = %s.%s", from, st.srcCols[j], aliasRef, st.tgtCols[j])
			}
		}
	}

	detail := "via foreign key"
	if len(p.steps) > 1 {
		var hops []string
		for _, st := range p.steps {
			hops = append(hops, st.table.Name)
		}
		detail = "via " + strings.Join(hops, " → ")
	}
	return b.String(), detail
}

func qualifiedRef(t TableInfo) string {
	if t.Schema == "public" {
		return t.Name
	}
	return t.Schema + "." + t.Name
}

// generateAlias picks a short unused alias, mirroring what people type.
func generateAlias(name string, used map[string]bool) string {
	base := ""
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			base = strings.ToLower(string(r))
			break
		}
	}
	if base == "" {
		base = "t"
	}
	if !used[base] {
		return base
	}
	for i := 1; ; i++ {
		cand := fmt.Sprintf("%s%d", base, i)
		if !used[cand] {
			return cand
		}
	}
}

func usedAliases(refs []tableRef) map[string]bool {
	used := map[string]bool{}
	for _, r := range refs {
		if r.Alias != "" {
			used[strings.ToLower(r.Alias)] = true
		}
		used[strings.ToLower(r.Name)] = true
	}
	return used
}

// adjacentTables marks relations directly FK-related to anything in scope.
func adjacentTables(cat *Catalog, inScope []tableRef) map[string]bool {
	out := map[string]bool{}
	for _, ref := range inScope {
		t, ok := cat.lookup(ref.Schema, ref.Name)
		if !ok {
			continue
		}
		for _, fk := range cat.fksFor(t.Schema, t.Name) {
			out[strings.ToLower(fk.SrcSchema+"."+fk.SrcTable)] = true
			out[strings.ToLower(fk.TgtSchema+"."+fk.TgtTable)] = true
		}
	}
	return out
}

// boostJoinColumns lifts the columns that a foreign key says join the relation
// to something already in the statement.
func boostJoinColumns(out []Completion, cat *Catalog, cc caretContext, ref TableInfo) {
	joinCols := map[string]bool{}
	for _, other := range cc.Tables {
		ot, ok := cat.lookup(other.Schema, other.Name)
		if !ok || strings.EqualFold(ot.Qualified(), ref.Qualified()) {
			continue
		}
		for _, fk := range cat.ForeignKeys {
			switch {
			case strings.EqualFold(fk.SrcTable, ref.Name) && strings.EqualFold(fk.TgtTable, ot.Name):
				for _, c := range fk.SrcCols {
					joinCols[strings.ToLower(c)] = true
				}
			case strings.EqualFold(fk.TgtTable, ref.Name) && strings.EqualFold(fk.SrcTable, ot.Name):
				for _, c := range fk.TgtCols {
					joinCols[strings.ToLower(c)] = true
				}
			}
		}
	}
	for i := range out {
		if joinCols[strings.ToLower(out[i].Label)] {
			out[i].Boost += boostJoinColumn
			out[i].Detail = out[i].Detail + " · joins"
		}
	}
}

// resolveRef maps an alias or relation name used in the statement back to a
// catalog relation.
func resolveRef(cat *Catalog, inScope []tableRef, handle string) (TableInfo, bool) {
	if handle == "" {
		return TableInfo{}, false
	}
	for _, ref := range inScope {
		if strings.EqualFold(ref.Alias, handle) || strings.EqualFold(ref.Name, handle) {
			if t, ok := cat.lookup(ref.Schema, ref.Name); ok {
				return t, true
			}
		}
	}
	// Not aliased in the statement — maybe a bare relation name.
	return cat.lookup("", handle)
}

func refHandle(r tableRef) string {
	if r.Alias != "" {
		return r.Alias
	}
	return r.Name
}

// columnCompletion builds one column suggestion. qualifier, when non-empty,
// is the alias or relation name the label is prefixed with.
func columnCompletion(c ColumnInfo, t TableInfo, qualifier string) Completion {
	// Detail is the type alone: it sits in a narrow column beside the label,
	// and nullability pushed the popup wide enough to shove the info panel
	// over the list. It stays in the info panel instead.
	detail := c.Type
	info := fmt.Sprintf("%s.%s — %s", t.Qualified(), c.Name, c.Type)
	if c.NotNull {
		info += " not null"
	}
	if c.Default != "" {
		info += "\ndefault " + c.Default
	}
	if c.Comment != "" {
		info += "\n\n" + c.Comment
	}
	comp := Completion{
		Label:       c.Name,
		Detail:      detail,
		Type:        "property",
		Info:        info,
		Section:     sectionColumns,
		SectionRank: rankColumns,
	}
	if qualifier != "" {
		qualified := qualifier + "." + c.Name
		comp.DisplayLabel = qualified
		comp.Apply = qualified
	}
	return comp
}

func tableCompletion(t TableInfo, label string, boost float64) Completion {
	perms := []string{}
	if t.Select {
		perms = append(perms, "select")
	}
	if t.Insert {
		perms = append(perms, "insert")
	}
	if t.Update {
		perms = append(perms, "update")
	}
	if t.Delete {
		perms = append(perms, "delete")
	}
	detail := t.Schema
	info := t.Qualified()
	if len(perms) > 0 {
		info += " — " + strings.Join(perms, ", ")
	} else {
		info += " — no privileges"
	}
	return Completion{
		Label:       label,
		Detail:      detail,
		Type:        t.Kind,
		Info:        info,
		Boost:       boost,
		Section:     sectionTables,
		SectionRank: rankTables,
	}
}

// Matching.
//
// The typed text is matched against word boundaries, not by plain substring.
// A substring test looks harmless and is not: "e" appears somewhere inside
// almost every identifier and keyword, so it matched nearly the whole catalog
// and the popup became a wall of text that CodeMirror could only reorder, not
// shorten.
//
// The tiers below are what people actually mean when they type a few
// characters — the start of the thing, the start of the part after a
// qualifier, the start of a word within it, or its initials — and anything
// that matches none of them is dropped rather than ranked low.
const (
	matchExact    = 90 // the whole label
	matchPrefix   = 70 // "cust" → customers
	matchTail     = 60 // "cust" → o.customer_id
	matchSegment  = 35 // "at"   → created_at, "by" → GROUP BY
	matchInitials = 10 // "ca"   → created_at
)

// labelSegments splits an identifier into its words: dots, underscores,
// spaces, and hyphens separate, and so do camelCase humps.
func labelSegments(label string) []string {
	var segs []string
	var cur []rune
	runes := []rune(label)

	flush := func() {
		if len(cur) > 0 {
			segs = append(segs, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}

	for i, r := range runes {
		switch r {
		case '.', '_', ' ', '-':
			flush()
			continue
		}
		// A capital following a lower-case letter starts a new word, so
		// camelCase identifiers segment the same way snake_case ones do.
		if i > 0 && unicode.IsUpper(r) && unicode.IsLower(runes[i-1]) {
			flush()
		}
		cur = append(cur, r)
	}
	flush()
	return segs
}

// matchLabel scores how well pattern matches label, reporting false when it
// does not match at all. pattern must already be lower-cased.
func matchLabel(label, pattern string) (float64, bool) {
	if pattern == "" {
		return 0, true
	}
	lower := strings.ToLower(label)
	if len(pattern) > len(lower) {
		return 0, false
	}
	if lower == pattern {
		return matchExact, true
	}
	if strings.HasPrefix(lower, pattern) {
		return matchPrefix, true
	}
	// The part after a qualifier: typing "cust" should reach o.customer_id.
	if i := strings.LastIndex(lower, "."); i >= 0 {
		if strings.HasPrefix(lower[i+1:], pattern) {
			return matchTail, true
		}
	}

	// Segment the original label, not the lower-cased copy: folding case
	// first erases the camelCase humps that mark word boundaries.
	segs := labelSegments(label)
	for _, seg := range segs {
		if strings.HasPrefix(seg, pattern) {
			return matchSegment, true
		}
	}

	// Initials, for multi-word identifiers only: "ca" → created_at. Requiring
	// two characters and two segments keeps single letters from matching
	// everything again by the back door.
	if len(pattern) >= 2 && len(segs) >= 2 {
		var initials []rune
		for _, seg := range segs {
			initials = append(initials, []rune(seg)[0])
		}
		if strings.HasPrefix(string(initials), pattern) {
			return matchInitials, true
		}
	}

	return 0, false
}

// filterAndRank applies the typed text and caps the payload. CodeMirror
// filters again client-side, but it can only narrow what it was sent, so
// matching properly here is what keeps the list short.
func filterAndRank(opts []Completion, prefix string) []Completion {
	if prefix != "" {
		filtered := opts[:0:0]
		for _, o := range opts {
			boost, ok := matchLabel(o.Label, prefix)
			if !ok {
				continue
			}
			o.Boost += boost
			filtered = append(filtered, o)
		}
		opts = filtered
	}
	// Order by section, then boost, so truncating at the cap drops the least
	// relevant tier rather than an arbitrary slice of everything.
	sort.SliceStable(opts, func(i, j int) bool {
		if opts[i].SectionRank != opts[j].SectionRank {
			return opts[i].SectionRank < opts[j].SectionRank
		}
		return opts[i].Boost > opts[j].Boost
	})
	if len(opts) > maxCompletions {
		opts = opts[:maxCompletions]
	}
	return opts
}
