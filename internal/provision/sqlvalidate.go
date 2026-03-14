package provision

import (
	"fmt"
	"strings"
	"unicode"
)

// tokenKind represents the type of a SQL token.
type tokenKind int

const (
	tokWord   tokenKind = iota // keyword or identifier (letters, digits, underscores)
	tokDot                     // .
	tokComma                   // ,
	tokStar                    // *
	tokRolePH                  // {role}
)

// token is a single lexical element.
type token struct {
	kind tokenKind
	text string // original text, lowercased for words
}

// maxIdentifierLen is the maximum length of a single identifier (PG limit is 63).
const maxIdentifierLen = 128

// maxTokens is the maximum number of tokens allowed in a single statement.
const maxTokens = 64

// isASCIILetter returns true for a-z, A-Z only. We reject non-ASCII letters
// to prevent unicode homoglyph attacks (e.g. Cyrillic 'а' mimicking Latin 'a').
func isASCIILetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// isASCIIDigit returns true for 0-9 only.
func isASCIIDigit(ch rune) bool {
	return ch >= '0' && ch <= '9'
}

func tokenize(input string) ([]token, error) {
	var tokens []token
	i := 0
	runes := []rune(input)
	n := len(runes)

	for i < n {
		ch := runes[i]

		// Skip ASCII whitespace only: space, tab, newline, carriage return.
		// Reject unicode whitespace (non-breaking space, ogham space, etc.)
		// to prevent hidden token boundary tricks.
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			i++
			continue
		}
		if unicode.IsSpace(ch) {
			return nil, fmt.Errorf("non-ASCII whitespace character U+%04X at position %d", ch, i)
		}

		// {role} placeholder.
		if ch == '{' {
			if i+5 < n && string(runes[i:i+6]) == "{role}" {
				tokens = append(tokens, token{kind: tokRolePH, text: "{role}"})
				i += 6
				continue
			}
			return nil, fmt.Errorf("unexpected '{' at position %d (only {role} is allowed)", i)
		}

		// Dot.
		if ch == '.' {
			tokens = append(tokens, token{kind: tokDot, text: "."})
			i++
			continue
		}

		// Comma.
		if ch == ',' {
			tokens = append(tokens, token{kind: tokComma, text: ","})
			i++
			continue
		}

		// Star.
		if ch == '*' {
			tokens = append(tokens, token{kind: tokStar, text: "*"})
			i++
			continue
		}

		// Word: [a-zA-Z_][a-zA-Z0-9_]* — ASCII only.
		if ch == '_' || isASCIILetter(ch) {
			start := i
			for i < n && (runes[i] == '_' || isASCIILetter(runes[i]) || isASCIIDigit(runes[i])) {
				i++
			}
			if i-start > maxIdentifierLen {
				return nil, fmt.Errorf("identifier too long (%d chars) at position %d", i-start, start)
			}
			word := strings.ToLower(string(runes[start:i]))
			tokens = append(tokens, token{kind: tokWord, text: word})
			continue
		}

		return nil, fmt.Errorf("unexpected character %q at position %d", ch, i)
	}

	if len(tokens) > maxTokens {
		return nil, fmt.Errorf("too many tokens (%d, max %d)", len(tokens), maxTokens)
	}

	return tokens, nil
}

// validateSQL checks that every statement is a valid GRANT, REVOKE, or
// ALTER DEFAULT PRIVILEGES statement. It uses a strict tokenizer that rejects
// any characters outside the expected set, then validates the token structure.
func validateSQL(statements []string) error {
	for _, stmt := range statements {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			return fmt.Errorf("empty sql statement")
		}

		tokens, err := tokenize(trimmed)
		if err != nil {
			return fmt.Errorf("invalid sql %q: %w", stmt, err)
		}

		if len(tokens) == 0 {
			return fmt.Errorf("empty sql statement")
		}

		if err := validateTokens(tokens, stmt); err != nil {
			return err
		}
	}
	return nil
}

// validateTokens checks that the token stream matches one of:
//
//	GRANT <privileges> ON <target> TO {role}
//	REVOKE <privileges> ON <target> FROM {role}
//	ALTER DEFAULT PRIVILEGES [FOR ROLE <name>] [IN SCHEMA <name>] GRANT|REVOKE ...
func validateTokens(tokens []token, original string) error {
	if len(tokens) == 0 {
		return fmt.Errorf("empty statement")
	}

	first := wordText(tokens[0])
	switch first {
	case "grant":
		return validateGrantRevoke(tokens, original, true)
	case "revoke":
		return validateGrantRevoke(tokens, original, false)
	case "alter":
		return validateAlterDefaultPrivileges(tokens, original)
	default:
		return fmt.Errorf("sql statement must start with GRANT, REVOKE, or ALTER DEFAULT PRIVILEGES: %s", original)
	}
}

// validateGrantRevoke validates:
//
//	GRANT <privileges> ON <target> TO <role_list>
//	REVOKE <privileges> ON <target> FROM <role_list>
//
// Where <privileges> is a comma-separated list of privilege keywords,
// <target> is an object specification, and <role_list> ends with {role}.
func validateGrantRevoke(tokens []token, original string, isGrant bool) error {
	// Find ON keyword to split privileges from target.
	onIdx := -1
	for i, t := range tokens {
		if i == 0 {
			continue
		}
		if wordText(t) == "on" {
			onIdx = i
			break
		}
	}
	if onIdx < 0 {
		return fmt.Errorf("missing ON keyword: %s", original)
	}

	// Privileges: tokens between GRANT/REVOKE and ON.
	privTokens := tokens[1:onIdx]
	if len(privTokens) == 0 {
		return fmt.Errorf("missing privileges: %s", original)
	}
	if err := validatePrivilegeList(privTokens, original); err != nil {
		return err
	}

	// Find TO (grant) or FROM (revoke) to split target from role.
	targetKeyword := "to"
	if !isGrant {
		targetKeyword = "from"
	}
	toIdx := -1
	for i := onIdx + 1; i < len(tokens); i++ {
		if wordText(tokens[i]) == targetKeyword {
			toIdx = i
			break
		}
	}
	if toIdx < 0 {
		return fmt.Errorf("missing %s keyword: %s", strings.ToUpper(targetKeyword), original)
	}

	// Target: tokens between ON and TO/FROM.
	targetTokens := tokens[onIdx+1 : toIdx]
	if len(targetTokens) == 0 {
		return fmt.Errorf("missing target object: %s", original)
	}
	if err := validateTarget(targetTokens, original); err != nil {
		return err
	}

	// Role: tokens after TO/FROM — must end with {role}.
	roleTokens := tokens[toIdx+1:]
	return validateRoleRef(roleTokens, original)
}

// validateAlterDefaultPrivileges validates:
//
//	ALTER DEFAULT PRIVILEGES [FOR ROLE <name>] [IN SCHEMA <name>] GRANT|REVOKE ...
func validateAlterDefaultPrivileges(tokens []token, original string) error {
	if len(tokens) < 4 {
		return fmt.Errorf("incomplete ALTER DEFAULT PRIVILEGES: %s", original)
	}
	if wordText(tokens[1]) != "default" || wordText(tokens[2]) != "privileges" {
		return fmt.Errorf("expected ALTER DEFAULT PRIVILEGES: %s", original)
	}

	// Consume optional FOR ROLE <name> and IN SCHEMA <name> clauses.
	i := 3
	for i < len(tokens) {
		switch wordText(tokens[i]) {
		case "for":
			// FOR ROLE <name>
			if i+2 >= len(tokens) || wordText(tokens[i+1]) != "role" {
				return fmt.Errorf("expected FOR ROLE <name>: %s", original)
			}
			if tokens[i+2].kind != tokWord {
				return fmt.Errorf("expected role name after FOR ROLE: %s", original)
			}
			i += 3
		case "in":
			// IN SCHEMA <name>[, <name>...]
			if i+2 >= len(tokens) || wordText(tokens[i+1]) != "schema" {
				return fmt.Errorf("expected IN SCHEMA <name>: %s", original)
			}
			i += 2
			if i >= len(tokens) || tokens[i].kind != tokWord {
				return fmt.Errorf("expected schema name after IN SCHEMA: %s", original)
			}
			i++
			// Allow comma-separated schema names.
			for i+1 < len(tokens) && tokens[i].kind == tokComma && tokens[i+1].kind == tokWord {
				i += 2
			}
		default:
			goto done
		}
	}
done:

	// Remaining tokens must be a GRANT or REVOKE statement.
	if i >= len(tokens) {
		return fmt.Errorf("missing GRANT or REVOKE in ALTER DEFAULT PRIVILEGES: %s", original)
	}

	remaining := tokens[i:]
	w := wordText(remaining[0])
	if w == "grant" {
		return validateGrantRevoke(remaining, original, true)
	}
	if w == "revoke" {
		return validateGrantRevoke(remaining, original, false)
	}
	return fmt.Errorf("expected GRANT or REVOKE after ALTER DEFAULT PRIVILEGES: %s", original)
}

// privilegeKeywords lists valid SQL privilege names.
var privilegeKeywords = map[string]bool{
	"select":     true,
	"insert":     true,
	"update":     true,
	"delete":     true,
	"truncate":   true,
	"references": true,
	"trigger":    true,
	"create":     true,
	"connect":    true,
	"temporary":  true,
	"temp":       true,
	"execute":    true,
	"usage":      true,
	"all":        true,
	"privileges": true, // for ALL PRIVILEGES
}

// specificPrivileges lists privileges that can appear individually.
var specificPrivileges = map[string]bool{
	"select":     true,
	"insert":     true,
	"update":     true,
	"delete":     true,
	"truncate":   true,
	"references": true,
	"trigger":    true,
	"create":     true,
	"connect":    true,
	"temporary":  true,
	"temp":       true,
	"execute":    true,
	"usage":      true,
}

// validatePrivilegeList checks that tokens form a valid comma-separated
// privilege list. Accepts either:
//   - ALL [PRIVILEGES]
//   - privilege [, privilege ...]
//
// Rejects: consecutive commas, ALL mixed with specifics, bare PRIVILEGES.
func validatePrivilegeList(tokens []token, original string) error {
	if len(tokens) == 0 {
		return fmt.Errorf("empty privilege list: %s", original)
	}

	// Handle ALL [PRIVILEGES].
	if wordText(tokens[0]) == "all" {
		if len(tokens) == 1 {
			return nil // just ALL
		}
		if len(tokens) == 2 && wordText(tokens[1]) == "privileges" {
			return nil // ALL PRIVILEGES
		}
		return fmt.Errorf("ALL cannot be combined with other privileges: %s", original)
	}

	// Specific privileges: must alternate word, comma, word, comma, ...
	// No consecutive commas, no leading/trailing commas.
	expectWord := true
	for _, t := range tokens {
		if expectWord {
			if t.kind != tokWord {
				return fmt.Errorf("expected privilege keyword, got %q: %s", t.text, original)
			}
			if !specificPrivileges[t.text] {
				return fmt.Errorf("unknown privilege %q: %s", t.text, original)
			}
			expectWord = false
		} else {
			if t.kind != tokComma {
				return fmt.Errorf("expected comma between privileges, got %q: %s", t.text, original)
			}
			expectWord = true
		}
	}
	if expectWord {
		return fmt.Errorf("privilege list ends with comma: %s", original)
	}
	return nil
}

// objectTypeKeywords are optional prefixes for specific object targets.
var objectTypeKeywords = map[string]bool{
	"table":    true,
	"sequence": true,
	"function": true,
	"routine":  true,
	"type":     true,
}

// allObjectTypes are the plural forms used in ALL <type> IN SCHEMA patterns.
var allObjectTypes = map[string]bool{
	"tables":    true,
	"sequences": true,
	"functions": true,
	"routines":  true,
	"types":     true,
}

// validateTarget checks that tokens form a valid PG grant target. Accepted
// patterns:
//
//	[TABLE|SEQUENCE|FUNCTION|ROUTINE|TYPE] <qname>[, <qname>...]
//	ALL TABLES|SEQUENCES|FUNCTIONS|ROUTINES|TYPES IN SCHEMA <name>[, <name>...]
//	SCHEMA <name>[, <name>...]
//	DATABASE <name>
//
// Where <qname> is name or schema.name (max 2 parts).
func validateTarget(tokens []token, original string) error {
	if len(tokens) == 0 {
		return fmt.Errorf("missing target: %s", original)
	}

	// Reject {role} anywhere in target.
	for _, t := range tokens {
		if t.kind == tokRolePH {
			return fmt.Errorf("{role} placeholder not allowed in target: %s", original)
		}
	}

	first := wordText(tokens[0])

	// ALL <type> IN SCHEMA <name>[, <name>...]
	if first == "all" {
		return validateAllInSchema(tokens[1:], original)
	}

	// SCHEMA <name>[, <name>...]
	if first == "schema" {
		return validateNameList(tokens[1:], original, 1) // schema names are unqualified
	}

	// DATABASE <name>
	if first == "database" {
		if len(tokens) != 2 || tokens[1].kind != tokWord {
			return fmt.Errorf("DATABASE requires exactly one name: %s", original)
		}
		return nil
	}

	// Optional object type prefix: TABLE, SEQUENCE, FUNCTION, ROUTINE, TYPE.
	start := 0
	if objectTypeKeywords[first] {
		start = 1
	}

	// Qualified name list: name[.name][, name[.name]...]
	return validateNameList(tokens[start:], original, 2)
}

// validateAllInSchema validates: <type> IN SCHEMA <name>[, <name>...]
// (tokens should NOT include the leading ALL).
func validateAllInSchema(tokens []token, original string) error {
	// Need at least: <type> IN SCHEMA <name> = 4 tokens.
	if len(tokens) < 4 {
		return fmt.Errorf("incomplete ALL ... IN SCHEMA target: %s", original)
	}
	if !allObjectTypes[wordText(tokens[0])] {
		return fmt.Errorf("expected TABLES, SEQUENCES, FUNCTIONS, ROUTINES, or TYPES after ALL: %s", original)
	}
	if wordText(tokens[1]) != "in" {
		return fmt.Errorf("expected IN after ALL %s: %s", tokens[0].text, original)
	}
	if wordText(tokens[2]) != "schema" {
		return fmt.Errorf("expected SCHEMA after IN: %s", original)
	}
	// Remaining tokens are schema name list (unqualified).
	return validateNameList(tokens[3:], original, 1)
}

// validateNameList validates a comma-separated list of names. maxParts controls
// how many dot-separated parts are allowed (1 = unqualified, 2 = schema.name).
func validateNameList(tokens []token, original string, maxParts int) error {
	if len(tokens) == 0 {
		return fmt.Errorf("missing name in target: %s", original)
	}

	// State machine: expect a name, then optionally .name, then optionally comma.
	i := 0
	for {
		// Expect a word (first part of name).
		if i >= len(tokens) || tokens[i].kind != tokWord {
			return fmt.Errorf("expected identifier in target: %s", original)
		}
		i++
		parts := 1

		// Optional: .name (second part).
		if maxParts >= 2 && i+1 < len(tokens) && tokens[i].kind == tokDot {
			if tokens[i+1].kind != tokWord {
				return fmt.Errorf("expected identifier after dot: %s", original)
			}
			i += 2
			parts = 2
			_ = parts
		}

		// Check for unexpected dots (too many parts).
		if i < len(tokens) && tokens[i].kind == tokDot {
			return fmt.Errorf("too many dot-separated parts in name: %s", original)
		}

		// End of list or comma for next name.
		if i >= len(tokens) {
			return nil
		}
		if tokens[i].kind != tokComma {
			return fmt.Errorf("unexpected token %q in target name list: %s", tokens[i].text, original)
		}
		i++ // consume comma
		// Must have another name after comma.
		if i >= len(tokens) {
			return fmt.Errorf("target name list ends with comma: %s", original)
		}
	}
}

// validateRoleRef checks that the role reference is exactly {role} with no
// other tokens. This prevents granting to additional roles beyond the
// provisioned one (e.g. "TO admin, {role}" would grant to admin too).
func validateRoleRef(tokens []token, original string) error {
	if len(tokens) == 0 {
		return fmt.Errorf("missing role reference: %s", original)
	}
	if len(tokens) != 1 {
		return fmt.Errorf("role reference must be exactly {role}, got %d tokens: %s", len(tokens), original)
	}
	if tokens[0].kind != tokRolePH {
		return fmt.Errorf("role reference must be {role}: %s", original)
	}
	return nil
}

// wordText returns the lowercased text if the token is a word, or empty string.
func wordText(t token) string {
	if t.kind == tokWord {
		return t.text
	}
	return ""
}
