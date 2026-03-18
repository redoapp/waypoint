package provision

import (
	"fmt"
	"strings"

	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/parser"
	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/privilege"
	"github.com/cockroachdb/cockroachdb-parser/pkg/sql/sem/tree"
)

// rolePlaceholder is substituted for {{.Role}} before parsing so the parser sees a valid identifier.
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

		if strings.ContainsRune(trimmed, 0) {
			return fmt.Errorf("null bytes are not allowed: %s", stmt)
		}

		// Render template placeholders with valid identifiers for parsing.
		prepared, err := renderSQL(trimmed, SQLTemplateData{Role: rolePlaceholder})
		if err != nil {
			return fmt.Errorf("invalid sql %q: %w", stmt, err)
		}

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
		return fmt.Errorf("role reference must be exactly {{.Role}}: %s", original)
	}
	if grantees[0].RoleSpecType != tree.RoleName {
		return fmt.Errorf("role reference must be exactly {{.Role}}: %s", original)
	}
	if !strings.EqualFold(grantees[0].Name, rolePlaceholder) {
		return fmt.Errorf("role reference must be {{.Role}}: %s", original)
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
					return fmt.Errorf("{{.Role}} placeholder not allowed in target: %s", original)
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
			return fmt.Errorf("{{.Role}} placeholder not allowed in target: %s", original)
		}
	}

	// Reject placeholder in database targets.
	for _, d := range targets.Databases {
		if strings.EqualFold(string(d), rolePlaceholder) {
			return fmt.Errorf("{{.Role}} placeholder not allowed in target: %s", original)
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
