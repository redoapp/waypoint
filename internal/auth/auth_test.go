package auth

import (
	"testing"
	"time"
)

func TestMergeRules_SingleRuleWithPG(t *testing.T) {
	rules := []CapRule{{
		Backends: []string{"pg-main"},
		PG: &PGCap{
			Databases: map[string]DBPermissions{
				"app_db": {Permissions: []string{"SELECT ON ALL TABLES IN SCHEMA public"}},
			},
		},
		Limits: &LimitsCap{MaxConns: 5},
	}}

	perms, limits := mergeRules(rules)

	if len(perms) != 1 || perms[0] != "SELECT ON ALL TABLES IN SCHEMA public" {
		t.Errorf("unexpected perms: %v", perms)
	}
	if limits.MaxConns != 5 {
		t.Errorf("expected MaxConns=5, got %d", limits.MaxConns)
	}
}

func TestMergeRules_MultipleRulesMergePermissions(t *testing.T) {
	rules := []CapRule{
		{
			Backends: []string{"pg-main"},
			PG: &PGCap{
				Databases: map[string]DBPermissions{
					"app_db": {Permissions: []string{"SELECT ON ALL TABLES IN SCHEMA public"}},
				},
			},
			Limits: &LimitsCap{MaxConns: 10, MaxBytesPerConn: 1000},
		},
		{
			Backends: []string{"pg-main"},
			PG: &PGCap{
				Databases: map[string]DBPermissions{
					"app_db": {Permissions: []string{"INSERT ON ALL TABLES IN SCHEMA public"}},
				},
			},
			Limits: &LimitsCap{MaxConns: 5, MaxBytesPerConn: 2000},
		},
	}

	perms, limits := mergeRules(rules)

	if len(perms) != 2 {
		t.Fatalf("expected 2 perms, got %d: %v", len(perms), perms)
	}
	// Most restrictive limits win.
	if limits.MaxConns != 5 {
		t.Errorf("expected MaxConns=5 (most restrictive), got %d", limits.MaxConns)
	}
	if limits.MaxBytesPerConn != 1000 {
		t.Errorf("expected MaxBytesPerConn=1000 (most restrictive), got %d", limits.MaxBytesPerConn)
	}
}

func TestMergeRules_NoLimits(t *testing.T) {
	rules := []CapRule{{
		Backends: []string{"raw-tcp"},
	}}

	perms, limits := mergeRules(rules)

	if len(perms) != 0 {
		t.Errorf("expected no perms, got %v", perms)
	}
	if limits.MaxConns != 0 {
		t.Errorf("expected zero MaxConns, got %d", limits.MaxConns)
	}
}

func TestMergeRules_NoPG(t *testing.T) {
	rules := []CapRule{{
		Backends: []string{"raw-tcp"},
		Limits:   &LimitsCap{MaxConns: 10},
	}}

	perms, limits := mergeRules(rules)

	if len(perms) != 0 {
		t.Errorf("expected no perms for non-PG rule, got %v", perms)
	}
	if limits.MaxConns != 10 {
		t.Errorf("expected MaxConns=10, got %d", limits.MaxConns)
	}
}

func TestMergeLimits_MostRestrictiveWins(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{MaxConns: 10, MaxConnDuration: "2h"})
	mergeLimits(&m, &LimitsCap{MaxConns: 5, MaxConnDuration: "1h"})

	if m.MaxConns != 5 {
		t.Errorf("expected 5, got %d", m.MaxConns)
	}
	if m.MaxConnDuration != time.Hour {
		t.Errorf("expected 1h, got %v", m.MaxConnDuration)
	}
}

func TestMergeLimits_FirstValueSetsBaseline(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{MaxBytesPerConn: 500})

	if m.MaxBytesPerConn != 500 {
		t.Errorf("expected 500, got %d", m.MaxBytesPerConn)
	}
}

func TestMergeLimits_LargerValueDoesNotOverride(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{MaxConns: 5})
	mergeLimits(&m, &LimitsCap{MaxConns: 10})

	if m.MaxConns != 5 {
		t.Errorf("expected 5 (smaller), got %d", m.MaxConns)
	}
}

func TestMergeLimits_ZeroDoesNotOverride(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{MaxConns: 5})
	mergeLimits(&m, &LimitsCap{MaxConns: 0})

	if m.MaxConns != 5 {
		t.Errorf("expected 5 (zero should not override), got %d", m.MaxConns)
	}
}

func TestMergeLimits_Bandwidth(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: &BandwidthCap{Bytes: 1_000_000, Period: "1h"},
	})

	if m.BandwidthBytes != 1_000_000 {
		t.Errorf("expected 1000000, got %d", m.BandwidthBytes)
	}
	if m.BandwidthPeriod != time.Hour {
		t.Errorf("expected 1h, got %v", m.BandwidthPeriod)
	}
}

func TestMergeLimits_BandwidthMostRestrictive(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: &BandwidthCap{Bytes: 2_000_000, Period: "1h"},
	})
	mergeLimits(&m, &LimitsCap{
		Bandwidth: &BandwidthCap{Bytes: 1_000_000, Period: "1h"},
	})

	if m.BandwidthBytes != 1_000_000 {
		t.Errorf("expected 1000000 (most restrictive), got %d", m.BandwidthBytes)
	}
}

func TestMergeLimits_InvalidDurationIgnored(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{MaxConnDuration: "not-a-duration"})

	if m.MaxConnDuration != 0 {
		t.Errorf("expected 0 for invalid duration, got %v", m.MaxConnDuration)
	}
}

func TestDatabasePermissions_ExactMatch(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{{
			Backends: []string{"pg-main"},
			PG: &PGCap{
				Databases: map[string]DBPermissions{
					"app_db":    {Permissions: []string{"SELECT ON public.users"}},
					"analytics": {Permissions: []string{"SELECT ON public.events"}},
				},
			},
		}},
	}

	perms := DatabasePermissions(result, "app_db")
	if len(perms) != 1 || perms[0] != "SELECT ON public.users" {
		t.Errorf("unexpected perms for app_db: %v", perms)
	}

	perms = DatabasePermissions(result, "analytics")
	if len(perms) != 1 || perms[0] != "SELECT ON public.events" {
		t.Errorf("unexpected perms for analytics: %v", perms)
	}
}

func TestDatabasePermissions_WildcardMatch(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{{
			Backends: []string{"pg-main"},
			PG: &PGCap{
				Databases: map[string]DBPermissions{
					"*": {Permissions: []string{"SELECT ON ALL TABLES IN SCHEMA public"}},
				},
			},
		}},
	}

	perms := DatabasePermissions(result, "any_database")
	if len(perms) != 1 {
		t.Errorf("wildcard should match any database, got: %v", perms)
	}
}

func TestDatabasePermissions_ExactAndWildcardMerge(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{{
			Backends: []string{"pg-main"},
			PG: &PGCap{
				Databases: map[string]DBPermissions{
					"app_db": {Permissions: []string{"INSERT ON public.users"}},
					"*":      {Permissions: []string{"SELECT ON ALL TABLES IN SCHEMA public"}},
				},
			},
		}},
	}

	perms := DatabasePermissions(result, "app_db")
	if len(perms) != 2 {
		t.Errorf("expected exact + wildcard merged, got %d perms: %v", len(perms), perms)
	}
}

func TestDatabasePermissions_NoMatch(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{{
			Backends: []string{"pg-main"},
			PG: &PGCap{
				Databases: map[string]DBPermissions{
					"app_db": {Permissions: []string{"SELECT ON public.users"}},
				},
			},
		}},
	}

	perms := DatabasePermissions(result, "secret_db")
	if perms != nil {
		t.Errorf("expected nil for unmatched database, got: %v", perms)
	}
}

func TestDatabasePermissions_NoPGCap(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{{
			Backends: []string{"raw-tcp"},
		}},
	}

	perms := DatabasePermissions(result, "any_db")
	if perms != nil {
		t.Errorf("expected nil for non-PG rule, got: %v", perms)
	}
}

func TestDatabasePermissions_MultipleRulesMerge(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{
			{
				Backends: []string{"pg-main"},
				PG: &PGCap{
					Databases: map[string]DBPermissions{
						"app_db": {Permissions: []string{"SELECT ON public.users"}},
					},
				},
			},
			{
				Backends: []string{"pg-main"},
				PG: &PGCap{
					Databases: map[string]DBPermissions{
						"app_db": {Permissions: []string{"INSERT ON public.users"}},
					},
				},
			},
		},
	}

	perms := DatabasePermissions(result, "app_db")
	if len(perms) != 2 {
		t.Errorf("expected 2 perms from merged rules, got %d: %v", len(perms), perms)
	}
}

func TestMergeRules_MultipleDBs(t *testing.T) {
	rules := []CapRule{{
		Backends: []string{"pg-main"},
		PG: &PGCap{
			Databases: map[string]DBPermissions{
				"db1": {Permissions: []string{"perm1"}},
				"db2": {Permissions: []string{"perm2", "perm3"}},
			},
		},
	}}

	perms, _ := mergeRules(rules)

	if len(perms) != 3 {
		t.Errorf("expected 3 total perms across all DBs, got %d: %v", len(perms), perms)
	}
}
