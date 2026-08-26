package web

import (
	"strings"
	"unicode"
)

// This file holds the lightweight SQL scanner the console uses for editor
// assistance. It deliberately does not use the full parser: completions and
// statement splitting have to work on text that is mid-edit and therefore
// usually does not parse. Anything that requires a valid statement (kind
// classification, table extraction for the permission lint) goes through
// querylog.Analyze instead.

type tokenKind int

const (
	tokWord tokenKind = iota
	tokPunct
	tokString
	tokNumber
	tokComment
)

type token struct {
	Kind  tokenKind
	Text  string
	Start int
	End   int
}

// tokenize splits SQL into tokens, tracking string literals, dollar-quoted
// bodies, and both comment styles so that a semicolon or keyword inside them
// is never mistaken for structure.
func tokenize(sql string) []token {
	var toks []token
	r := []rune(sql)
	// Byte offsets are what the editor speaks, so track them alongside the
	// rune index rather than converting after the fact.
	byteOff := make([]int, len(r)+1)
	b := 0
	for i, c := range r {
		byteOff[i] = b
		b += len(string(c))
	}
	byteOff[len(r)] = b

	i := 0
	for i < len(r) {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++

		case c == '-' && i+1 < len(r) && r[i+1] == '-':
			start := i
			for i < len(r) && r[i] != '\n' {
				i++
			}
			toks = append(toks, token{tokComment, string(r[start:i]), byteOff[start], byteOff[i]})

		case c == '/' && i+1 < len(r) && r[i+1] == '*':
			start := i
			i += 2
			depth := 1
			for i < len(r) && depth > 0 {
				if r[i] == '/' && i+1 < len(r) && r[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if r[i] == '*' && i+1 < len(r) && r[i+1] == '/' {
					depth--
					i += 2
					continue
				}
				i++
			}
			toks = append(toks, token{tokComment, string(r[start:i]), byteOff[start], byteOff[i]})

		case c == '\'' || c == '"':
			quote := c
			start := i
			i++
			for i < len(r) {
				if r[i] == quote {
					// Doubled quote is an escaped quote, not a terminator.
					if i+1 < len(r) && r[i+1] == quote {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			kind := tokString
			if quote == '"' {
				// A double-quoted identifier is a word for our purposes.
				kind = tokWord
			}
			toks = append(toks, token{kind, string(r[start:i]), byteOff[start], byteOff[i]})

		case c == '$':
			if tag, ok := dollarTag(r, i); ok {
				start := i
				i += len(tag)
				closeAt := indexRunes(r, i, tag)
				if closeAt < 0 {
					i = len(r)
				} else {
					i = closeAt + len(tag)
				}
				toks = append(toks, token{tokString, string(r[start:i]), byteOff[start], byteOff[i]})
				continue
			}
			start := i
			i++
			toks = append(toks, token{tokPunct, string(r[start:i]), byteOff[start], byteOff[i]})

		case unicode.IsDigit(c):
			start := i
			for i < len(r) && (unicode.IsDigit(r[i]) || r[i] == '.') {
				i++
			}
			toks = append(toks, token{tokNumber, string(r[start:i]), byteOff[start], byteOff[i]})

		case isIdentStart(c):
			start := i
			for i < len(r) && isIdentPart(r[i]) {
				i++
			}
			toks = append(toks, token{tokWord, string(r[start:i]), byteOff[start], byteOff[i]})

		default:
			start := i
			i++
			toks = append(toks, token{tokPunct, string(r[start:i]), byteOff[start], byteOff[i]})
		}
	}
	return toks
}

func isIdentStart(c rune) bool {
	return unicode.IsLetter(c) || c == '_'
}

func isIdentPart(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '_' || c == '$'
}

// dollarTag reports the full $tag$ marker starting at i, if there is one.
func dollarTag(r []rune, i int) ([]rune, bool) {
	if r[i] != '$' {
		return nil, false
	}
	j := i + 1
	for j < len(r) && (isIdentPart(r[j]) && r[j] != '$') {
		j++
	}
	if j < len(r) && r[j] == '$' {
		return r[i : j+1], true
	}
	return nil, false
}

func indexRunes(hay []rune, from int, needle []rune) int {
	for i := from; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// stmtSpan is one statement's extent within the buffer, in byte offsets.
type stmtSpan struct {
	Start int
	End   int
	Text  string
}

// splitStatements breaks a buffer on top-level semicolons. Semicolons inside
// strings, comments, dollar-quoted bodies, or parentheses do not split.
func splitStatements(sql string) []stmtSpan {
	toks := tokenize(sql)
	var spans []stmtSpan
	depth := 0
	start := -1
	last := 0

	flush := func(end int) {
		if start < 0 {
			return
		}
		text := strings.TrimSpace(sql[start:end])
		if text != "" {
			spans = append(spans, stmtSpan{Start: start, End: end, Text: text})
		}
		start = -1
	}

	for _, t := range toks {
		if t.Kind == tokComment {
			continue
		}
		if start < 0 {
			start = t.Start
		}
		switch {
		case t.Kind == tokPunct && t.Text == "(":
			depth++
		case t.Kind == tokPunct && t.Text == ")":
			if depth > 0 {
				depth--
			}
		case t.Kind == tokPunct && t.Text == ";" && depth == 0:
			flush(t.End)
			last = t.End
		}
		if t.End > last {
			last = t.End
		}
	}
	flush(len(sql))
	return spans
}

// statementAt returns the statement containing (or immediately preceding) the
// caret. This is what powers "run the statement under the cursor".
func statementAt(sql string, pos int) (stmtSpan, bool) {
	spans := splitStatements(sql)
	if len(spans) == 0 {
		return stmtSpan{}, false
	}
	if pos < 0 {
		pos = 0
	}
	if pos > len(sql) {
		pos = len(sql)
	}
	for _, s := range spans {
		if pos >= s.Start && pos <= s.End {
			return s, true
		}
	}
	// Caret sits past the final statement (trailing whitespace).
	return spans[len(spans)-1], true
}

// tableRef is a relation named in a FROM/JOIN/UPDATE/INTO clause, with the
// alias the statement bound it to.
type tableRef struct {
	Schema string
	Name   string
	Alias  string
}

// Qualified renders the reference the way the catalog keys tables.
func (t tableRef) Qualified() string {
	if t.Schema == "" {
		return t.Name
	}
	return t.Schema + "." + t.Name
}

// completionKind is what the caret position calls for.
type completionKind int

const (
	kindUnknown completionKind = iota
	// kindStatementStart: nothing has been typed yet in this statement, so
	// what belongs here is a statement verb — SELECT, INSERT, WITH — not a
	// relation name.
	kindStatementStart
	// kindColumnOf: caret follows "alias." — complete that relation's columns.
	kindColumnOf
	// kindTable: caret is where a relation name belongs.
	kindTable
	// kindJoinTarget: caret follows JOIN — relation name, FK-ranked, with an
	// ON clause attached.
	kindJoinTarget
	// kindExpression: caret is anywhere a column or function may appear.
	kindExpression
)

// caretContext describes what to offer at the caret.
type caretContext struct {
	Kind      completionKind
	Prefix    string // word already typed, to be replaced
	Qualifier string // the "o" in "o.|"
	From      int    // byte offset where the replacement starts
	Tables    []tableRef
	AfterOn   bool // caret is inside a JOIN ... ON predicate
}

var clauseKeywords = map[string]bool{
	"select": true, "from": true, "where": true, "group": true, "having": true,
	"order": true, "limit": true, "offset": true, "join": true, "inner": true,
	"left": true, "right": true, "full": true, "cross": true, "lateral": true,
	"on": true, "using": true, "union": true, "intersect": true, "except": true,
	"insert": true, "into": true, "update": true, "set": true, "delete": true,
	"values": true, "returning": true, "with": true, "as": true, "and": true,
	"or": true, "not": true, "natural": true, "outer": true, "window": true,
	"fetch": true, "for": true, "distinct": true,
}

// analyzeCaret works out what belongs at pos. It scans tokens rather than
// parsing, because a buffer being edited rarely parses.
func analyzeCaret(sql string, pos int) caretContext {
	if pos < 0 {
		pos = 0
	}
	if pos > len(sql) {
		pos = len(sql)
	}
	span, ok := statementAt(sql, pos)
	if !ok {
		// Nothing in the buffer at all.
		return caretContext{Kind: kindStatementStart, From: pos}
	}
	if pos > span.End {
		// The caret sits past the previous statement's terminator, so a new
		// statement begins here. Returning early also keeps the previous
		// statement's relations from leaking into scope.
		return caretContext{Kind: kindStatementStart, From: pos}
	}
	stmt := sql[span.Start:span.End]
	rel := pos - span.Start
	if rel < 0 {
		rel = 0
	}
	if rel > len(stmt) {
		rel = len(stmt)
	}

	ctx := caretContext{From: pos, Tables: extractTables(stmt)}

	toks := tokenize(stmt)
	// Keep only tokens that start before the caret, and note whether the
	// caret is sitting inside the last one (mid-word).
	var before []token
	for _, t := range toks {
		if t.Kind == tokComment {
			continue
		}
		if t.Start < rel {
			before = append(before, t)
		}
	}
	if len(before) == 0 {
		ctx.Kind = kindStatementStart
		return ctx
	}

	last := before[len(before)-1]
	// A word the caret is inside (or immediately after) is the prefix.
	if last.Kind == tokWord && last.End >= rel {
		ctx.Prefix = stmt[last.Start:rel]
		ctx.From = span.Start + last.Start
		before = before[:len(before)-1]
	} else if last.Kind == tokPunct && last.Text == "." && last.End == rel {
		// "alias.|" — no prefix yet.
		ctx.From = pos
	}

	// A single partial word with nothing before it starts the statement.
	if len(before) == 0 {
		ctx.Kind = kindStatementStart
		return ctx
	}

	// Qualified reference: <word> "." [prefix]
	if n := len(before); n >= 2 {
		if before[n-1].Kind == tokPunct && before[n-1].Text == "." && before[n-2].Kind == tokWord {
			ctx.Qualifier = unquoteIdent(before[n-2].Text)
			ctx.Kind = kindColumnOf
			ctx.AfterOn = lastClauseIs(before, "on")
			return ctx
		}
	}

	// Otherwise the preceding keyword decides.
	prevWord := ""
	prevPrevWord := ""
	for i := len(before) - 1; i >= 0; i-- {
		if before[i].Kind == tokWord {
			if prevWord == "" {
				prevWord = strings.ToLower(unquoteIdent(before[i].Text))
				continue
			}
			prevPrevWord = strings.ToLower(unquoteIdent(before[i].Text))
			break
		}
		if before[i].Kind == tokPunct && (before[i].Text == "," || before[i].Text == "(") {
			if prevWord == "" {
				prevWord = before[i].Text
			}
			break
		}
	}

	switch {
	case prevWord == "join":
		ctx.Kind = kindJoinTarget
	case prevWord == "from" || prevWord == "into" || prevWord == "update" || prevWord == "table":
		ctx.Kind = kindTable
	case prevWord == "," && lastClauseIs(before, "from"):
		ctx.Kind = kindTable
	case prevWord == "on" || prevPrevWord == "on":
		ctx.Kind = kindExpression
		ctx.AfterOn = true
	default:
		ctx.Kind = kindExpression
		ctx.AfterOn = lastClauseIs(before, "on")
	}
	return ctx
}

// lastClauseIs reports whether the most recent clause keyword is want.
func lastClauseIs(toks []token, want string) bool {
	for i := len(toks) - 1; i >= 0; i-- {
		if toks[i].Kind != tokWord {
			continue
		}
		w := strings.ToLower(unquoteIdent(toks[i].Text))
		if clauseKeywords[w] {
			return w == want
		}
	}
	return false
}

func unquoteIdent(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return strings.ReplaceAll(s[1:len(s)-1], `""`, `"`)
	}
	return s
}

// extractTables pulls relation references out of FROM/JOIN/UPDATE/INTO
// clauses, including their aliases. It tolerates incomplete statements.
func extractTables(stmt string) []tableRef {
	toks := tokenize(stmt)
	var refs []tableRef
	seen := map[string]bool{}

	readRef := func(i int) (tableRef, int) {
		var ref tableRef
		if i >= len(toks) || toks[i].Kind != tokWord {
			return ref, i
		}
		first := unquoteIdent(toks[i].Text)
		if clauseKeywords[strings.ToLower(first)] {
			return ref, i
		}
		ref.Name = first
		i++
		// schema.table
		if i+1 < len(toks) && toks[i].Kind == tokPunct && toks[i].Text == "." && toks[i+1].Kind == tokWord {
			ref.Schema = ref.Name
			ref.Name = unquoteIdent(toks[i+1].Text)
			i += 2
		}
		// optional AS
		if i < len(toks) && toks[i].Kind == tokWord && strings.EqualFold(toks[i].Text, "as") {
			i++
		}
		// alias
		if i < len(toks) && toks[i].Kind == tokWord {
			cand := unquoteIdent(toks[i].Text)
			if !clauseKeywords[strings.ToLower(cand)] {
				ref.Alias = cand
				i++
			}
		}
		return ref, i
	}

	for i := 0; i < len(toks); i++ {
		if toks[i].Kind != tokWord {
			continue
		}
		w := strings.ToLower(unquoteIdent(toks[i].Text))
		if w != "from" && w != "join" && w != "update" && w != "into" {
			continue
		}
		j := i + 1
		for {
			ref, next := readRef(j)
			if ref.Name == "" {
				break
			}
			key := ref.Qualified() + "\x00" + ref.Alias
			if !seen[key] {
				seen[key] = true
				refs = append(refs, ref)
			}
			j = next
			// FROM a, b, c
			if j < len(toks) && toks[j].Kind == tokPunct && toks[j].Text == "," {
				j++
				continue
			}
			break
		}
		i = j - 1
	}
	return refs
}
