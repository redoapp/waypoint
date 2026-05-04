package provision

import (
	"fmt"
	"strings"
)

// MongoPresetNames lists all recognized MongoDB preset names.
var MongoPresetNames = []string{"readonly", "readwrite", "admin"}

// MongoRole represents a MongoDB role assignment.
type MongoRole struct {
	Role string `bson:"role"`
	DB   string `bson:"db"`
}

// ExpandMongoPresets expands preset names into MongoDB role assignments
// for the given database.
func ExpandMongoPresets(presets []string, database string) ([]MongoRole, error) {
	var roles []MongoRole
	seen := make(map[string]bool)

	for _, preset := range presets {
		mongoRoles, ok := mongoPresetRoles[strings.ToLower(preset)]
		if !ok {
			return nil, fmt.Errorf("unknown MongoDB preset %q; valid presets: %s",
				preset, strings.Join(MongoPresetNames, ", "))
		}
		for _, tmpl := range mongoRoles {
			role := MongoRole{Role: tmpl.Role, DB: database}
			key := role.Role + ":" + role.DB
			if !seen[key] {
				seen[key] = true
				roles = append(roles, role)
			}
		}
	}

	return roles, nil
}

// mongoPresetRoles maps preset names to MongoDB role templates.
// The DB field is filled in by ExpandMongoPresets.
var mongoPresetRoles = map[string][]MongoRole{
	"readonly": {
		{Role: "read"},
	},
	"readwrite": {
		{Role: "readWrite"},
	},
	"admin": {
		{Role: "dbOwner"},
	},
}
