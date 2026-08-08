package provision

import (
	"fmt"
	"regexp"
	"strings"
)

// validSchemaName matches simple SQL identifiers (no quotes, no dots, no special chars).
var validSchemaName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// PresetNames lists all recognized preset names.
var PresetNames = []string{"readonly", "readwrite", "admin"}

// presetTemplates maps preset name to GRANT fragments with {schema} placeholder.
var presetTemplates = map[string][]string{
	"readonly": {
		"USAGE ON SCHEMA {schema}",
		"SELECT ON ALL TABLES IN SCHEMA {schema}",
		"SELECT ON ALL SEQUENCES IN SCHEMA {schema}",
	},
	"readwrite": {
		"USAGE ON SCHEMA {schema}",
		"SELECT ON ALL TABLES IN SCHEMA {schema}",
		"SELECT ON ALL SEQUENCES IN SCHEMA {schema}",
		"INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema}",
		"USAGE ON ALL SEQUENCES IN SCHEMA {schema}",
	},
	"admin": {
		"ALL PRIVILEGES ON ALL TABLES IN SCHEMA {schema}",
		"ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA {schema}",
		"USAGE, CREATE ON SCHEMA {schema}",
	},
}

// presetDefaultPrivileges maps preset name to the per-object-type grant
// clauses that mirror presetTemplates. They are applied via ALTER DEFAULT
// PRIVILEGES so that tables and sequences created in the future by a
// configured creator role automatically carry the same privileges the
// preset grants on objects that already exist. Schema-level grants
// (USAGE/CREATE ON SCHEMA) have no ALTER DEFAULT PRIVILEGES analogue and
// are deliberately omitted.
var presetDefaultPrivileges = map[string][]string{
	"readonly": {
		"SELECT ON TABLES",
		"SELECT ON SEQUENCES",
	},
	"readwrite": {
		"SELECT, INSERT, UPDATE, DELETE ON TABLES",
		"USAGE, SELECT ON SEQUENCES",
	},
	"admin": {
		"ALL PRIVILEGES ON TABLES",
		"ALL PRIVILEGES ON SEQUENCES",
	},
}

// defaultPrivilegeGrants returns the "ON <object-type>" grant clauses for a
// preset, suitable for composition as:
//
//	ALTER DEFAULT PRIVILEGES FOR ROLE <creator> IN SCHEMA <schema> GRANT <clause> TO <group>
//
// It returns nil for an unrecognized preset.
func defaultPrivilegeGrants(preset string) []string {
	return presetDefaultPrivileges[strings.ToLower(preset)]
}

// ExpandPresets expands preset names into GRANT fragments for the given schemas.
// Returns fragments suitable for use as: GRANT <fragment> TO <role>.
func ExpandPresets(presets []string, schemas []string) ([]string, error) {
	if len(schemas) == 0 {
		schemas = []string{"public"}
	}

	for _, s := range schemas {
		if !validSchemaName.MatchString(s) {
			return nil, fmt.Errorf("invalid schema name %q: must be a simple identifier", s)
		}
	}

	var fragments []string
	seen := make(map[string]bool)

	for _, preset := range presets {
		templates, ok := presetTemplates[strings.ToLower(preset)]
		if !ok {
			return nil, fmt.Errorf("%s", presetHint(preset))
		}
		for _, tmpl := range templates {
			for _, schema := range schemas {
				frag := strings.ReplaceAll(tmpl, "{schema}", schema)
				if !seen[frag] {
					seen[frag] = true
					fragments = append(fragments, frag)
				}
			}
		}
	}

	return fragments, nil
}
