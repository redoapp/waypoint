package provision

import (
	"strings"
	"testing"

	"github.com/redoapp/waypoint/internal/auth"
)

func TestExpandOpenSearchPermissions_PresetsAndRaw(t *testing.T) {
	spec, err := ExpandOpenSearchPermissions(&auth.OpenSearchCap{
		ClusterPermissions: []string{"cluster:monitor/main"},
		Indices: map[string]auth.OpenSearchIndexPermissions{
			"logs-*": {
				Permissions:    []string{"readwrite"},
				AllowedActions: []string{"indices:data/read/search"},
				FLS:            []string{"message", "timestamp"},
			},
		},
		Tenants: map[string]auth.OpenSearchTenantPermissions{
			"global_tenant": {AllowedActions: []string{"kibana_all_read"}},
		},
	})
	if err != nil {
		t.Fatalf("ExpandOpenSearchPermissions: %v", err)
	}
	if !containsString(spec.ClusterPermissions, "cluster_composite_ops") {
		t.Fatalf("cluster permissions = %v, want readwrite cluster action", spec.ClusterPermissions)
	}
	if !containsString(spec.ClusterPermissions, "cluster:monitor/main") {
		t.Fatalf("cluster permissions = %v, want raw cluster action", spec.ClusterPermissions)
	}
	if len(spec.IndexPermissions) != 1 {
		t.Fatalf("index permission count = %d", len(spec.IndexPermissions))
	}
	actions := spec.IndexPermissions[0].AllowedActions
	for _, want := range []string{"read", "write", "create_index", "indices:data/read/search"} {
		if !containsString(actions, want) {
			t.Fatalf("actions = %v, missing %q", actions, want)
		}
	}
	if len(spec.TenantPermissions) != 1 || spec.TenantPermissions[0].TenantPatterns[0] != "global_tenant" {
		t.Fatalf("tenant permissions = %+v", spec.TenantPermissions)
	}
}

func TestExpandOpenSearchPermissions_Admin(t *testing.T) {
	spec, err := ExpandOpenSearchPermissions(&auth.OpenSearchCap{
		Indices: map[string]auth.OpenSearchIndexPermissions{
			"*": {Permissions: []string{"admin"}},
		},
	})
	if err != nil {
		t.Fatalf("ExpandOpenSearchPermissions: %v", err)
	}
	if !containsString(spec.ClusterPermissions, "cluster_all") {
		t.Fatalf("cluster permissions = %v, want cluster_all", spec.ClusterPermissions)
	}
	if len(spec.IndexPermissions) != 1 || !containsString(spec.IndexPermissions[0].AllowedActions, "indices_all") {
		t.Fatalf("index permissions = %+v, want indices_all", spec.IndexPermissions)
	}
}

func TestExpandOpenSearchPermissions_InvalidPreset(t *testing.T) {
	_, err := ExpandOpenSearchPermissions(&auth.OpenSearchCap{
		Indices: map[string]auth.OpenSearchIndexPermissions{
			"logs-*": {Permissions: []string{"superuser"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown OpenSearch preset") {
		t.Fatalf("expected invalid preset error, got %v", err)
	}
}

func TestOpenSearchRoleSignature_NormalizesEquivalentSpecs(t *testing.T) {
	a := OpenSearchRoleSpec{
		ClusterPermissions: []string{"cluster_composite_ops_ro"},
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"logs-a"}, AllowedActions: []string{"read"}},
			{IndexPatterns: []string{"logs-b"}, AllowedActions: []string{"read"}},
		},
	}
	b := OpenSearchRoleSpec{
		IndexPermissions: []OpenSearchIndexPermissionSpec{
			{IndexPatterns: []string{"logs-b", "logs-a"}, AllowedActions: []string{"read", "read"}},
		},
		ClusterPermissions: []string{"cluster_composite_ops_ro", "cluster_composite_ops_ro"},
	}

	if OpenSearchRoleSignature(a) != OpenSearchRoleSignature(b) {
		t.Fatalf("equivalent specs produced different signatures:\n%s\n%s", OpenSearchRoleSignature(a), OpenSearchRoleSignature(b))
	}
	if OpenSearchRoleName(a) != OpenSearchRoleName(b) {
		t.Fatalf("equivalent specs produced different role names")
	}
}

func TestOpenSearchFormatUsername(t *testing.T) {
	p := &OpenSearchProvisioner{userPrefix: "wp_os_"}
	name := p.formatUsername("Alice.Example@example.com", "work-node")
	if !strings.HasPrefix(name, "wp_os_") {
		t.Fatalf("name = %q, want wp_os_ prefix", name)
	}
	if strings.ContainsAny(name, "@.-") {
		t.Fatalf("name = %q, want sanitized identifier", name)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
