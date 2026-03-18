package provision

import (
	"fmt"
	"strings"

	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/parser"
	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/privilege"
	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/sem/tree"
)

// rolePlaceholder replaces {role} before parsing so the parser sees a valid identifier.
const rolePlaceholder = "__wp_role_placeholder__"

// allowedPrivileges is the set of privilege kinds we permit (CockroachDB-recognized subset).
var allowedPrivileges = map[privilege.Kind]bool{
	privilege.ALL:     true,
	privilege.SELECT:  true,
	privilege.INSERT:  true,
	privilege.DELETE:  true,
	privilege.UPDATE:  true,
	privilege.CREATE:  true,
	privilege.CONNECT: true,
	privilege.EXECUTE: true,
	privilege.USAGE:   true,
	privilege.TRIGGER: true,
}

// pgOnlyPrivileges are PostgreSQL privileges not recognized by the CockroachDB parser.
// We validate these ourselves and substitute them before parsing.
var pgOnlyPrivileges = map[string]string{
	"truncate":   "SELECT",
	"references": "SELECT",
	"temporary":  "CONNECT",
	"temp":       "CONNECT",
}

// maxStatementLen limits the total length of a single SQL statement
// to prevent resource abuse.
const maxStatementLen = 4096

// validateSQL checks that every statement is a valid GRANT, REVOKE, or
// ALTER DEFAULT PRIVILEGES statement using the CockroachDB SQL parser
// for structural validation and AST-based security checks.
func validateSQL(statements []string) error {
	for _, stmt := range statements {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			return fmt.Errorf("empty sql statement")
		}

		if len(trimmed) > maxStatementLen {
			return fmt.Errorf("sql statement too long (%d chars, max %d)", len(trimmed), maxStatementLen)
		}

		// Reject dangerous characters before parsing. The parser would accept
		// some of these (comments, quoted identifiers) but we reject them
		// as a defense-in-depth measure.
		if err := rejectDangerousInput(trimmed, stmt); err != nil {
			return err
		}

		// Pre-validate and substitute PG-only privilege keywords and other
		// syntax not recognized by the CockroachDB parser.
		prepared, err := prepareForParsing(trimmed)
		if err != nil {
			return fmt.Errorf("invalid sql %q: %w", stmt, err)
		}

		// Replace {role} placeholder with a valid identifier.
		prepared = strings.ReplaceAll(prepared, "{role}", rolePlaceholder)

		parsed, err := parser.ParseOne(prepared)
		if err != nil {
			return fmt.Errorf("invalid sql %q: %w", stmt, err)
		}

		if err := validateAST(parsed.AST, stmt); err != nil {
			return err
		}
	}
	return nil
}

// rejectDangerousInput checks for characters and patterns that the parser
// would accept but that we want to reject for security reasons.
func rejectDangerousInput(sql, original string) error {
	if strings.Contains(sql, "\"") {
		return fmt.Errorf("quoted identifiers are not allowed: %s", original)
	}
	if strings.Contains(sql, "--") {
		return fmt.Errorf("comments are not allowed: %s", original)
	}
	if strings.Contains(sql, "/*") {
		return fmt.Errorf("comments are not allowed: %s", original)
	}
	if strings.ContainsRune(sql, 0) {
		return fmt.Errorf("null bytes are not allowed: %s", original)
	}
	if strings.Contains(sql, ";") {
		return fmt.Errorf("semicolons are not allowed: %s", original)
	}
	return nil
}

// prepareForParsing handles syntax differences between PostgreSQL and
// CockroachDB. It validates PG-only privilege keywords against our allowlist,
// substitutes them with CockroachDB equivalents, and transforms unsupported
// syntax like ALL ROUTINES IN SCHEMA.
func prepareForParsing(sql string) (string, error) {
	upper := strings.ToUpper(sql)

	// Handle ROUTINES -> FUNCTIONS.
	// CockroachDB parser doesn't support the ROUTINES keyword.
	// This covers both "ALL ROUTINES IN SCHEMA" and "ON ROUTINES" in ALTER DEFAULT PRIVILEGES.
	if idx := indexOfWord(upper, "ROUTINES", 0); idx >= 0 {
		sql = sql[:idx] + "FUNCTIONS" + sql[idx+len("ROUTINES"):]
		upper = strings.ToUpper(sql)
	}

	// Find the privilege list region: between GRANT/REVOKE and ON.
	// For ALTER DEFAULT PRIVILEGES, look for the inner GRANT/REVOKE.
	privStart, privEnd := findPrivilegeRegion(upper)
	if privStart < 0 || privEnd < 0 {
		// No privilege region found — let the parser handle it.
		return sql, nil
	}

	// Extract and validate each privilege word.
	privRegion := sql[privStart:privEnd]
	words := splitPrivilegeWords(privRegion)

	var result []byte
	result = append(result, sql[:privStart]...)

	for _, w := range words {
		lower := strings.ToLower(strings.TrimSpace(w.text))

		if w.isSeparator {
			result = append(result, w.text...)
			continue
		}

		// "privileges" is allowed after ALL.
		if lower == "privileges" {
			result = append(result, w.text...)
			continue
		}

		if sub, ok := pgOnlyPrivileges[lower]; ok {
			result = append(result, sub...)
			// Pad with spaces if the replacement is shorter to maintain alignment.
			for j := len(sub); j < len(w.text); j++ {
				result = append(result, ' ')
			}
			continue
		}

		// Not a PG-only privilege; keep as-is. The parser will validate it.
		result = append(result, w.text...)
	}

	result = append(result, sql[privEnd:]...)
	return string(result), nil
}

type privWord struct {
	text        string
	isSeparator bool // comma or whitespace
}

// splitPrivilegeWords splits a privilege region into words and separators,
// preserving the original text for reconstruction.
func splitPrivilegeWords(region string) []privWord {
	var words []privWord
	i := 0
	for i < len(region) {
		// Consume whitespace/commas as separators.
		if region[i] == ' ' || region[i] == '\t' || region[i] == '\n' || region[i] == '\r' || region[i] == ',' {
			start := i
			for i < len(region) && (region[i] == ' ' || region[i] == '\t' || region[i] == '\n' || region[i] == '\r' || region[i] == ',') {
				i++
			}
			words = append(words, privWord{text: region[start:i], isSeparator: true})
			continue
		}
		// Consume a word.
		start := i
		for i < len(region) && region[i] != ' ' && region[i] != '\t' && region[i] != '\n' && region[i] != '\r' && region[i] != ',' {
			i++
		}
		words = append(words, privWord{text: region[start:i], isSeparator: false})
	}
	return words
}

// findPrivilegeRegion returns the byte offsets [start, end) of the privilege
// list in a SQL statement. The region is between GRANT/REVOKE and the
// following ON keyword.
func findPrivilegeRegion(upper string) (int, int) {
	// For ALTER DEFAULT PRIVILEGES, find the inner GRANT/REVOKE.
	searchFrom := 0
	if strings.HasPrefix(upper, "ALTER") {
		// Find GRANT or REVOKE after the ALTER DEFAULT PRIVILEGES prefix.
		idx := strings.Index(upper, "GRANT")
		if idx < 5 { // Must be after ALTER
			idx = strings.Index(upper, "REVOKE")
		}
		if idx < 0 {
			return -1, -1
		}
		searchFrom = idx
	}

	// Find GRANT or REVOKE keyword.
	grantIdx := indexOfWord(upper, "GRANT", searchFrom)
	revokeIdx := indexOfWord(upper, "REVOKE", searchFrom)

	kwIdx := -1
	kwLen := 0
	if grantIdx >= 0 && (revokeIdx < 0 || grantIdx < revokeIdx) {
		kwIdx = grantIdx
		kwLen = 5
	} else if revokeIdx >= 0 {
		kwIdx = revokeIdx
		kwLen = 6
	}
	if kwIdx < 0 {
		return -1, -1
	}

	privStart := kwIdx + kwLen

	// Find ON keyword after the privilege list.
	onIdx := indexOfWord(upper, "ON", privStart)
	if onIdx < 0 {
		return -1, -1
	}

	return privStart, onIdx
}

// indexOfWord finds the index of a keyword in the string, ensuring it's a whole word
// (not part of a larger identifier).
func indexOfWord(upper string, word string, from int) int {
	for i := from; i <= len(upper)-len(word); {
		idx := strings.Index(upper[i:], word)
		if idx < 0 {
			return -1
		}
		pos := i + idx
		// Check word boundaries.
		before := pos == 0 || !isIdentChar(upper[pos-1])
		after := pos+len(word) >= len(upper) || !isIdentChar(upper[pos+len(word)])
		if before && after {
			return pos
		}
		i = pos + 1
	}
	return -1
}

func isIdentChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}

// validateAST dispatches to type-specific validation.
func validateAST(ast tree.Statement, original string) error {
	switch stmt := ast.(type) {
	case *tree.Grant:
		return validateGrant(stmt, original)
	case *tree.Revoke:
		return validateRevoke(stmt, original)
	case *tree.AlterDefaultPrivileges:
		return validateAlterDefault(stmt, original)
	default:
		return fmt.Errorf("sql statement must start with GRANT, REVOKE, or ALTER DEFAULT PRIVILEGES: %s", original)
	}
}

func validateGrant(stmt *tree.Grant, original string) error {
	if stmt.WithGrantOption {
		return fmt.Errorf("WITH GRANT OPTION is not allowed: %s", original)
	}
	if err := validateGrantees(stmt.Grantees, original); err != nil {
		return err
	}
	if err := validatePrivileges(stmt.Privileges, original); err != nil {
		return err
	}
	if err := validateTargets(&stmt.Targets, original); err != nil {
		return err
	}
	return rejectQuotedIdentifiers(stmt, original)
}

func validateRevoke(stmt *tree.Revoke, original string) error {
	if stmt.GrantOptionFor {
		return fmt.Errorf("GRANT OPTION FOR is not allowed: %s", original)
	}
	if err := validateGrantees(stmt.Grantees, original); err != nil {
		return err
	}
	if err := validatePrivileges(stmt.Privileges, original); err != nil {
		return err
	}
	if err := validateTargets(&stmt.Targets, original); err != nil {
		return err
	}
	return rejectQuotedIdentifiers(stmt, original)
}

func validateAlterDefault(stmt *tree.AlterDefaultPrivileges, original string) error {
	if stmt.ForAllRoles {
		return fmt.Errorf("FOR ALL ROLES is not allowed: %s", original)
	}

	if stmt.IsGrant {
		g := &stmt.Grant
		if g.WithGrantOption {
			return fmt.Errorf("WITH GRANT OPTION is not allowed: %s", original)
		}
		if err := validateGrantees(g.Grantees, original); err != nil {
			return err
		}
		if err := validatePrivileges(g.Privileges, original); err != nil {
			return err
		}
		if err := validateAbbreviatedTarget(g.Target, original); err != nil {
			return err
		}
	} else {
		r := &stmt.Revoke
		if r.GrantOptionFor {
			return fmt.Errorf("GRANT OPTION FOR is not allowed: %s", original)
		}
		if err := validateGrantees(r.Grantees, original); err != nil {
			return err
		}
		if err := validatePrivileges(r.Privileges, original); err != nil {
			return err
		}
		if err := validateAbbreviatedTarget(r.Target, original); err != nil {
			return err
		}
	}

	return rejectQuotedIdentifiers(stmt, original)
}

// validateGrantees ensures exactly one grantee matching our placeholder.
func validateGrantees(grantees tree.RoleSpecList, original string) error {
	if len(grantees) != 1 {
		return fmt.Errorf("role reference must be exactly {role}: %s", original)
	}
	if grantees[0].RoleSpecType != tree.RoleName {
		return fmt.Errorf("role reference must be exactly {role}: %s", original)
	}
	if !strings.EqualFold(grantees[0].Name, rolePlaceholder) {
		return fmt.Errorf("role reference must be {role}: %s", original)
	}
	return nil
}

// validatePrivileges checks that all privileges are in our allowlist.
func validatePrivileges(privs privilege.List, original string) error {
	for _, p := range privs {
		if !allowedPrivileges[p] {
			return fmt.Errorf("privilege %v is not allowed: %s", p, original)
		}
	}
	return nil
}

// validateTargets ensures only allowed target types are used and names
// aren't too deeply qualified.
func validateTargets(targets *tree.GrantTargetList, original string) error {
	if len(targets.Functions) > 0 {
		return fmt.Errorf("FUNCTION targets are not allowed: %s", original)
	}
	if len(targets.Procedures) > 0 {
		return fmt.Errorf("PROCEDURE targets are not allowed: %s", original)
	}
	if targets.System {
		return fmt.Errorf("SYSTEM targets are not allowed: %s", original)
	}
	if len(targets.ExternalConnections) > 0 {
		return fmt.Errorf("EXTERNAL CONNECTION targets are not allowed: %s", original)
	}
	if len(targets.Types) > 0 {
		return fmt.Errorf("TYPE targets are not allowed: %s", original)
	}

	// Validate table/sequence name depth and reject placeholder in targets.
	for _, tp := range targets.Tables.TablePatterns {
		switch t := tp.(type) {
		case *tree.UnresolvedName:
			if t.NumParts > 2 {
				return fmt.Errorf("too many dot-separated parts in name: %s", original)
			}
			if t.Star {
				return fmt.Errorf("wildcard target is not allowed: %s", original)
			}
			// Check that none of the name parts match the role placeholder.
			for i := 0; i < t.NumParts; i++ {
				if strings.EqualFold(t.Parts[i], rolePlaceholder) {
					return fmt.Errorf("{role} placeholder not allowed in target: %s", original)
				}
			}
		case *tree.AllTablesSelector:
			// Reject bare * target (ALL TABLES IN SCHEMA is handled separately).
			return fmt.Errorf("wildcard target is not allowed: %s", original)
		}
	}

	// Reject catalog-qualified schema names and placeholder in schema targets.
	for _, s := range targets.Schemas {
		if s.ExplicitCatalog {
			return fmt.Errorf("catalog-qualified schema names are not allowed: %s", original)
		}
		if strings.EqualFold(string(s.SchemaName), rolePlaceholder) {
			return fmt.Errorf("{role} placeholder not allowed in target: %s", original)
		}
	}

	// Reject placeholder in database targets.
	for _, d := range targets.Databases {
		if strings.EqualFold(string(d), rolePlaceholder) {
			return fmt.Errorf("{role} placeholder not allowed in target: %s", original)
		}
	}

	return nil
}

// validateAbbreviatedTarget checks ALTER DEFAULT PRIVILEGES target types.
func validateAbbreviatedTarget(target privilege.TargetObjectType, original string) error {
	switch target {
	case privilege.Tables, privilege.Sequences, privilege.Types, privilege.Schemas, privilege.Routines:
		return nil
	default:
		return fmt.Errorf("unsupported target object type: %s", original)
	}
}

// rejectQuotedIdentifiers formats the AST and rejects if it contains
// double-quoted identifiers, preventing sneaky character injection.
func rejectQuotedIdentifiers(stmt tree.NodeFormatter, original string) error {
	ctx := tree.NewFmtCtx(tree.FmtSimple)
	ctx.FormatNode(stmt)
	formatted := ctx.CloseAndGetString()
	if strings.Contains(formatted, "\"") {
		return fmt.Errorf("quoted identifiers are not allowed: %s", original)
	}
	return nil
}
