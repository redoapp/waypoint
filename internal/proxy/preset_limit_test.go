package proxy

import (
	"strings"
	"testing"

	"github.com/redoapp/waypoint/internal/auth"
)

func TestPostgresPresetLimitFromStartup(t *testing.T) {
	tests := []struct {
		name       string
		params     map[string]string
		wantNil    bool
		wantPreset string
		wantErr    string
	}{
		{
			name:    "missing",
			params:  map[string]string{"database": "app"},
			wantNil: true,
		},
		{
			name:       "single",
			params:     map[string]string{postgresPresetLimitParam: "readonly"},
			wantPreset: "readonly",
		},
		{
			name:       "comma list uses strongest preset as cap",
			params:     map[string]string{postgresPresetLimitParam: "readonly, readwrite"},
			wantPreset: "readwrite",
		},
		{
			name:       "singular alias",
			params:     map[string]string{postgresPresetLimitParamAlias: "admin"},
			wantPreset: "admin",
		},
		{
			name:    "conflicting parameters",
			params:  map[string]string{postgresPresetLimitParam: "readonly", postgresPresetLimitParamAlias: "readwrite"},
			wantErr: "cannot both be set",
		},
		{
			name:    "unknown preset",
			params:  map[string]string{postgresPresetLimitParam: "owner"},
			wantErr: "unknown preset",
		},
		{
			name:    "empty",
			params:  map[string]string{postgresPresetLimitParam: " , "},
			wantErr: "must include at least one preset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := postgresPresetLimitFromStartup(tt.params)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil limit, got %#v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected limit")
			}
			if got.Preset != tt.wantPreset {
				t.Fatalf("Preset = %q, want %q", got.Preset, tt.wantPreset)
			}
		})
	}
}

func TestLimitDBPermissionsToPostgresPreset(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		limit       string
		want        []string
		wantErr     string
	}{
		{
			name:        "readwrite grant capped to readonly",
			permissions: []string{"readwrite"},
			limit:       "readonly",
			want:        []string{"readonly"},
		},
		{
			name:        "admin grant capped to readwrite",
			permissions: []string{"admin"},
			limit:       "readwrite",
			want:        []string{"readwrite"},
		},
		{
			name:        "higher cap cannot elevate readonly grant",
			permissions: []string{"readonly"},
			limit:       "admin",
			want:        []string{"readonly"},
		},
		{
			name:        "multiple grants use strongest authorized preset",
			permissions: []string{"readonly", "readwrite"},
			limit:       "admin",
			want:        []string{"readwrite"},
		},
		{
			name:    "raw sql only cannot satisfy preset limit",
			limit:   "readonly",
			wantErr: "no named preset permissions",
		},
		{
			name:        "unknown authorized preset",
			permissions: []string{"owner"},
			limit:       "readonly",
			wantErr:     "unknown preset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, err := parsePostgresPresetLimit(postgresPresetLimitParam, tt.limit)
			if err != nil {
				t.Fatalf("parse limit: %v", err)
			}
			perms := &auth.DBPermissions{
				Permissions: tt.permissions,
				Schemas:     []string{"public", "app"},
				SQL:         []string{"GRANT SELECT ON public.audit TO {{.Role}}"},
			}

			got, _, err := limitDBPermissionsToPostgresPreset(perms, limit)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Join(got.Permissions, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("Permissions = %v, want %v", got.Permissions, tt.want)
			}
			if strings.Join(got.Schemas, ",") != "public,app" {
				t.Fatalf("Schemas = %v", got.Schemas)
			}
			if len(got.SQL) != 0 {
				t.Fatalf("SQL should be dropped when preset limit is set, got %v", got.SQL)
			}
		})
	}
}
