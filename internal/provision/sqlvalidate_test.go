package provision

import (
	"strings"
	"testing"
)

func TestValidateSQL_Grants(t *testing.T) {
	valid := []struct {
		name string
		stmt string
	}{
		{"select on table", "GRANT SELECT ON public.users TO {{.Role}}"},
		{"insert on table", "GRANT INSERT ON public.users TO {{.Role}}"},
		{"update on table", "GRANT UPDATE ON public.users TO {{.Role}}"},
		{"delete on table", "GRANT DELETE ON public.users TO {{.Role}}"},
		{"truncate on table", "GRANT TRUNCATE ON public.users TO {{.Role}}"},
		{"references on table", "GRANT REFERENCES ON public.users TO {{.Role}}"},
		{"trigger on table", "GRANT TRIGGER ON public.users TO {{.Role}}"},
		{"multiple privileges", "GRANT SELECT, INSERT, UPDATE ON public.users TO {{.Role}}"},
		{"all privileges", "GRANT ALL PRIVILEGES ON public.users TO {{.Role}}"},
		{"all on table", "GRANT ALL ON public.users TO {{.Role}}"},
		{"usage on schema", "GRANT USAGE ON SCHEMA public TO {{.Role}}"},
		{"create on schema", "GRANT CREATE ON SCHEMA public TO {{.Role}}"},
		{"usage create on schema", "GRANT USAGE, CREATE ON SCHEMA public TO {{.Role}}"},
		{"connect on database", "GRANT CONNECT ON DATABASE mydb TO {{.Role}}"},
		{"temporary on database", "GRANT TEMPORARY ON DATABASE mydb TO {{.Role}}"},
		{"temp on database", "GRANT TEMP ON DATABASE mydb TO {{.Role}}"},
		{"create on database", "GRANT CREATE ON DATABASE mydb TO {{.Role}}"},
		{"all tables in schema", "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{.Role}}"},
		{"all sequences in schema", "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {{.Role}}"},
		{"all functions in schema", "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {{.Role}}"},
		{"all routines in schema", "GRANT EXECUTE ON ALL ROUTINES IN SCHEMA public TO {{.Role}}"},
		{"select insert on all tables", "GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO {{.Role}}"},
		{"unqualified table", "GRANT SELECT ON users TO {{.Role}}"},
		{"schema qualified table", "GRANT SELECT ON myschema.mytable TO {{.Role}}"},
		{"table keyword", "GRANT SELECT ON TABLE public.users TO {{.Role}}"},
		{"sequence keyword", "GRANT USAGE ON SEQUENCE public.my_seq TO {{.Role}}"},
		{"lowercase", "grant select on public.users to {{.Role}}"},
		{"mixed case", "Grant Select On Public.Users To {{.Role}}"},
		{"extra whitespace", "  GRANT  SELECT  ON  public.users  TO  {{.Role}}  "},
	}

	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			if err := validateSQL([]string{tt.stmt}); err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
		})
	}
}

func TestValidateSQL_Revokes(t *testing.T) {
	valid := []struct {
		name string
		stmt string
	}{
		{"select on table", "REVOKE SELECT ON public.users FROM {{.Role}}"},
		{"multiple privileges", "REVOKE SELECT, INSERT ON public.users FROM {{.Role}}"},
		{"all privileges", "REVOKE ALL PRIVILEGES ON public.users FROM {{.Role}}"},
		{"usage on schema", "REVOKE USAGE ON SCHEMA public FROM {{.Role}}"},
		{"all tables in schema", "REVOKE SELECT ON ALL TABLES IN SCHEMA public FROM {{.Role}}"},
		{"connect on database", "REVOKE CONNECT ON DATABASE mydb FROM {{.Role}}"},
	}

	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			if err := validateSQL([]string{tt.stmt}); err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
		})
	}
}

func TestValidateSQL_AlterDefaultPrivileges(t *testing.T) {
	valid := []struct {
		name string
		stmt string
	}{
		{"grant select on tables", "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {{.Role}}"},
		{"grant all on tables", "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO {{.Role}}"},
		{"grant usage on sequences", "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO {{.Role}}"},
		{"grant execute on functions", "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO {{.Role}}"},
		{"grant execute on routines", "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON ROUTINES TO {{.Role}}"},
		{"grant usage on types", "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON TYPES TO {{.Role}}"},
		{"revoke select on tables", "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM {{.Role}}"},
		{"for role clause", "ALTER DEFAULT PRIVILEGES FOR ROLE admin IN SCHEMA public GRANT SELECT ON TABLES TO {{.Role}}"},
		{"for role without schema", "ALTER DEFAULT PRIVILEGES FOR ROLE admin GRANT SELECT ON TABLES TO {{.Role}}"},
		{"schema without for role", "ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT SELECT ON TABLES TO {{.Role}}"},
		{"no optional clauses", "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO {{.Role}}"},
		{"multiple schemas", "ALTER DEFAULT PRIVILEGES IN SCHEMA public, analytics GRANT SELECT ON TABLES TO {{.Role}}"},
	}

	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			if err := validateSQL([]string{tt.stmt}); err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
		})
	}
}

func TestValidateSQL_RejectedStatementTypes(t *testing.T) {
	rejected := []struct {
		name string
		stmt string
	}{
		{"drop table", "DROP TABLE public.users"},
		{"drop schema", "DROP SCHEMA public"},
		{"drop database", "DROP DATABASE mydb"},
		{"drop role", "DROP ROLE myrole"},
		{"create table", "CREATE TABLE public.test (id int)"},
		{"create role", "CREATE ROLE hacker WITH SUPERUSER"},
		{"create database", "CREATE DATABASE evil"},
		{"alter table", "ALTER TABLE public.users ADD COLUMN x INT"},
		{"alter role", "ALTER ROLE admin WITH SUPERUSER"},
		{"delete", "DELETE FROM public.users"},
		{"insert", "INSERT INTO public.users VALUES (1)"},
		{"update", "UPDATE public.users SET name = 'x'"},
		{"select", "SELECT * FROM pg_shadow"},
		{"truncate", "TRUNCATE public.users"},
		{"copy", "COPY public.users TO '/tmp/out'"},
		{"execute", "EXECUTE my_plan"},
		{"explain", "EXPLAIN SELECT 1"},
		{"set", "SET ROLE admin"},
		{"reset", "RESET ROLE"},
		{"begin", "BEGIN"},
		{"commit", "COMMIT"},
		{"rollback", "ROLLBACK"},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQL([]string{tt.stmt})
			if err == nil {
				t.Errorf("expected rejection for %q", tt.stmt)
			}
		})
	}
}

func TestValidateSQL_InjectionAttempts(t *testing.T) {
	rejected := []struct {
		name string
		stmt string
	}{
		{"semicolon after valid", "GRANT SELECT ON public.users TO {{.Role}}; DROP TABLE public.users"},
		{"semicolon before valid", ";GRANT SELECT ON public.users TO {{.Role}}"},
		{"parenthesized subquery", "GRANT SELECT ON (SELECT tablename FROM pg_tables) TO {{.Role}}"},
		{"single quoted string", "GRANT SELECT ON 'public.users' TO {{.Role}}"},
		{"double quoted identifier", "GRANT SELECT ON \"public\".\"users\" TO {{.Role}}"},
		{"line comment", "GRANT SELECT ON public.users TO {{.Role}} -- drop table"},
		{"block comment", "GRANT SELECT ON public.users /* evil */ TO {{.Role}}"},
		{"dollar quoting", "GRANT SELECT ON $$evil$$ TO {{.Role}}"},
		{"backslash escape", "GRANT SELECT ON public\\.users TO {{.Role}}"},
		{"null byte", "GRANT SELECT ON public.users TO {{.Role}}\x00"},
		{"unicode escape", "GRANT SELECT ON U&\"\\0041\" TO {{.Role}}"},
		{"cast expression", "GRANT SELECT ON public.users::text TO {{.Role}}"},
		{"concatenation", "GRANT SELECT ON public.users || 'x' TO {{.Role}}"},
		{"function call", "GRANT EXECUTE ON FUNCTION pg_sleep(10) TO {{.Role}}"},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQL([]string{tt.stmt})
			if err == nil {
				t.Errorf("expected rejection for injection attempt: %q", tt.stmt)
			}
		})
	}
}

func TestValidateSQL_StructuralErrors(t *testing.T) {
	rejected := []struct {
		name string
		stmt string
	}{
		{"empty string", ""},
		{"whitespace only", "   \t\n  "},
		{"grant no privileges", "GRANT ON public.users TO {{.Role}}"},
		{"grant no on", "GRANT SELECT TO {{.Role}}"},
		{"grant no to", "GRANT SELECT ON public.users"},
		{"grant no target", "GRANT SELECT ON TO {{.Role}}"},
		{"grant no role ref", "GRANT SELECT ON public.users TO admin"},
		{"revoke no from", "REVOKE SELECT ON public.users"},
		{"revoke no role ref", "REVOKE SELECT ON public.users FROM admin"},
		{"alter missing default", "ALTER PRIVILEGES GRANT SELECT ON TABLES TO {{.Role}}"},
		{"alter missing privileges", "ALTER DEFAULT GRANT SELECT ON TABLES TO {{.Role}}"},
		{"alter default privileges no body", "ALTER DEFAULT PRIVILEGES IN SCHEMA public"},
		{"alter default privileges invalid body", "ALTER DEFAULT PRIVILEGES DROP TABLE foo"},
		{"alter for without role keyword", "ALTER DEFAULT PRIVILEGES FOR admin GRANT SELECT ON TABLES TO {{.Role}}"},
		{"alter in without schema keyword", "ALTER DEFAULT PRIVILEGES IN public GRANT SELECT ON TABLES TO {{.Role}}"},
		{"unknown privilege keyword", "GRANT SUPERUSER ON public.users TO {{.Role}}"},
		{"just grant keyword", "GRANT"},
		{"just revoke keyword", "REVOKE"},
		{"just alter keyword", "ALTER"},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQL([]string{tt.stmt})
			if err == nil {
				t.Errorf("expected rejection for structural error: %q", tt.stmt)
			}
		})
	}
}

func TestValidateSQL_Malicious(t *testing.T) {
	rejected := []struct {
		name string
		stmt string
	}{
		// Privilege escalation: grant to additional roles besides {{.Role}}.
		{"grant to extra role before placeholder", "GRANT SELECT ON public.users TO admin, {{.Role}}"},
		{"grant to extra role via group keyword", "GRANT SELECT ON public.users TO GROUP {{.Role}}"},
		{"revoke from extra role", "REVOKE SELECT ON public.users FROM admin, {{.Role}}"},

		// WITH GRANT OPTION allows the grantee to re-grant privileges.
		{"with grant option", "GRANT SELECT ON public.users TO {{.Role}} WITH GRANT OPTION"},
		{"with admin option", "GRANT somerole TO {{.Role}} WITH ADMIN OPTION"},

		// Role placeholder in wrong position — injects role name into target.
		{"role placeholder in target", "GRANT SELECT ON {{.Role}} TO {{.Role}}"},
		{"role placeholder as schema name", "GRANT USAGE ON SCHEMA {{.Role}} TO {{.Role}}"},

		// Degenerate targets.
		{"only star in target", "GRANT SELECT ON * TO {{.Role}}"},

		// Excessively long inputs (potential resource abuse).
		{"extremely long identifier", "GRANT SELECT ON " + strings.Repeat("a", 10000) + " TO {{.Role}}"},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQL([]string{tt.stmt})
			if err == nil {
				t.Errorf("expected rejection for malicious statement: %q", truncate(tt.stmt, 80))
			}
		})
	}

	// These are syntactically valid grants where PG enforces its own access
	// control. The parser allows them — PG will reject unauthorized access.
	allowed := []struct {
		name string
		stmt string
	}{
		{"system catalog table", "GRANT SELECT ON pg_catalog.pg_authid TO {{.Role}}"},
		{"pg_shadow", "GRANT SELECT ON pg_shadow TO {{.Role}}"},
		{"information_schema", "GRANT SELECT ON information_schema.role_table_grants TO {{.Role}}"},
		{"identifier named exec", "GRANT SELECT ON exec TO {{.Role}}"},
		{"identifier named drop", "GRANT SELECT ON drop.my_table TO {{.Role}}"},
	}

	for _, tt := range allowed {
		t.Run("allowed/"+tt.name, func(t *testing.T) {
			if err := validateSQL([]string{tt.stmt}); err != nil {
				t.Errorf("expected valid (PG enforces access), got error: %v", err)
			}
		})
	}
}

func TestValidateSQL_TargetEdgeCases(t *testing.T) {
	rejected := []struct {
		name string
		stmt string
	}{
		// Excessive depth (schema.table is max 2 parts).
		{"triple qualified", "GRANT SELECT ON a.b.c TO {{.Role}}"},
		{"quad qualified", "GRANT SELECT ON a.b.c.d TO {{.Role}}"},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQL([]string{tt.stmt})
			if err == nil {
				t.Errorf("expected rejection for target edge case: %q", tt.stmt)
			}
		})
	}
}

func TestValidateSQL_PrivilegeEdgeCases(t *testing.T) {
	rejected := []struct {
		name string
		stmt string
	}{
		// ALL mixed with specific privileges — PG doesn't allow this.
		{"all plus specific", "GRANT ALL, SELECT ON public.users TO {{.Role}}"},
		{"specific plus all", "GRANT SELECT, ALL ON public.users TO {{.Role}}"},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQL([]string{tt.stmt})
			if err == nil {
				t.Errorf("expected rejection for privilege edge case: %q", tt.stmt)
			}
		})
	}
}

func TestValidateSQL_MultipleStatements(t *testing.T) {
	// All valid.
	err := validateSQL([]string{
		"GRANT SELECT ON public.users TO {{.Role}}",
		"GRANT USAGE ON SCHEMA analytics TO {{.Role}}",
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {{.Role}}",
		"REVOKE DELETE ON public.users FROM {{.Role}}",
	})
	if err != nil {
		t.Errorf("all valid statements should pass: %v", err)
	}

	// First invalid stops validation.
	err = validateSQL([]string{
		"DROP TABLE public.users",
		"GRANT SELECT ON public.users TO {{.Role}}",
	})
	if err == nil {
		t.Error("should reject when first statement is invalid")
	}

	// Last invalid stops validation.
	err = validateSQL([]string{
		"GRANT SELECT ON public.users TO {{.Role}}",
		"SELECT 1",
	})
	if err == nil {
		t.Error("should reject when last statement is invalid")
	}
}

func TestValidateSQL_InvalidTemplate(t *testing.T) {
	rejected := []struct {
		name string
		stmt string
	}{
		{"unclosed action", "GRANT SELECT ON public.users TO {{.Role}"},
		{"unknown field", "GRANT SELECT ON public.users TO {{.Unknown}}"},
		{"function call in template", "GRANT SELECT ON public.users TO {{call .Role}}"},
	}

	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSQL([]string{tt.stmt})
			if err == nil {
				t.Errorf("expected rejection for invalid template: %q", tt.stmt)
			}
		})
	}
}

// truncate shortens a string for display in error messages.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
