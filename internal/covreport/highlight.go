package covreport

import (
	"go/scanner"
	"go/token"
	"html"
	"html/template"
	"strings"
)

// builtinTypes are common Go built-in type names to highlight.
var builtinTypes = map[string]bool{
	"bool": true, "byte": true, "complex64": true, "complex128": true,
	"error": true, "float32": true, "float64": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"rune": true, "string": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"uintptr": true, "any": true, "comparable": true,
}

// builtinFuncs are built-in function names to highlight.
var builtinFuncs = map[string]bool{
	"append": true, "cap": true, "clear": true, "close": true, "complex": true,
	"copy": true, "delete": true, "imag": true, "len": true, "make": true,
	"max": true, "min": true, "new": true, "panic": true, "print": true,
	"println": true, "real": true, "recover": true,
}

type syntaxToken struct {
	offset int
	end    int
	class  string
}

// highlightGoSource tokenizes Go source and returns one template.HTML per line
// with syntax-highlighting spans. Coverage background is applied by the outer
// span in the template; these inner spans only set text color.
func highlightGoSource(src []byte) []template.HTML {
	tokens := scanTokens(src)

	var buf strings.Builder
	lastEnd := 0
	for _, t := range tokens {
		// Text before this token.
		if t.offset > lastEnd {
			buf.WriteString(html.EscapeString(string(src[lastEnd:t.offset])))
		}
		// Token text — may span multiple lines (block comments, raw strings).
		tokenText := string(src[t.offset:t.end])
		parts := strings.Split(tokenText, "\n")
		for i, part := range parts {
			if i > 0 {
				buf.WriteByte('\n')
			}
			buf.WriteString(`<span class="syn-`)
			buf.WriteString(t.class)
			buf.WriteString(`">`)
			buf.WriteString(html.EscapeString(part))
			buf.WriteString(`</span>`)
		}
		lastEnd = t.end
	}
	// Remaining text after last token.
	if lastEnd < len(src) {
		buf.WriteString(html.EscapeString(string(src[lastEnd:])))
	}

	lines := strings.Split(buf.String(), "\n")
	result := make([]template.HTML, len(lines))
	for i, l := range lines {
		result[i] = template.HTML(l)
	}
	return result
}

func scanTokens(src []byte) []syntaxToken {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))

	var s scanner.Scanner
	s.Init(file, src, func(_ token.Position, _ string) {}, scanner.ScanComments)

	var tokens []syntaxToken
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}

		cls := tokenClass(tok, lit)
		if cls == "" {
			continue
		}

		offset := fset.Position(pos).Offset
		length := len(lit)
		if length == 0 {
			length = len(tok.String())
		}

		tokens = append(tokens, syntaxToken{
			offset: offset,
			end:    offset + length,
			class:  cls,
		})
	}
	return tokens
}

func tokenClass(tok token.Token, lit string) string {
	if tok == token.COMMENT {
		return "cmt"
	}
	if tok == token.STRING || tok == token.CHAR {
		return "str"
	}
	if tok == token.INT || tok == token.FLOAT || tok == token.IMAG {
		return "num"
	}
	if tok.IsKeyword() {
		return "kw"
	}
	if tok == token.IDENT {
		if builtinTypes[lit] {
			return "typ"
		}
		if builtinFuncs[lit] {
			return "bfn"
		}
		if lit == "nil" || lit == "true" || lit == "false" || lit == "iota" {
			return "kw"
		}
	}
	return ""
}
