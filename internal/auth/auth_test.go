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
		Bandwidth: []BandwidthCap{{Bytes: 1_000_000, Period: "1h"}},
	})

	if len(m.BandwidthTiers) != 1 {
		t.Fatalf("expected 1 tier, got %d", len(m.BandwidthTiers))
	}
	if m.BandwidthTiers[0].Bytes != 1_000_000 {
		t.Errorf("expected 1000000, got %d", m.BandwidthTiers[0].Bytes)
	}
	if m.BandwidthTiers[0].Period != time.Hour {
		t.Errorf("expected 1h, got %v", m.BandwidthTiers[0].Period)
	}
}

func TestMergeLimits_BandwidthMostRestrictive(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{{Bytes: 2_000_000, Period: "1h"}},
	})
	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{{Bytes: 1_000_000, Period: "1h"}},
	})

	if len(m.BandwidthTiers) != 1 {
		t.Fatalf("expected 1 tier (deduped by period), got %d", len(m.BandwidthTiers))
	}
	if m.BandwidthTiers[0].Bytes != 1_000_000 {
		t.Errorf("expected 1000000 (most restrictive), got %d", m.BandwidthTiers[0].Bytes)
	}
}

func TestMergeLimits_BandwidthMultipleTiers(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{
			{Bytes: 100_000_000, Period: "1h"},
			{Bytes: 10_000_000_000, Period: "168h"},
		},
	})

	if len(m.BandwidthTiers) != 2 {
		t.Fatalf("expected 2 tiers, got %d", len(m.BandwidthTiers))
	}
	if m.BandwidthTiers[0].Bytes != 100_000_000 {
		t.Errorf("expected hourly tier 100MB, got %d", m.BandwidthTiers[0].Bytes)
	}
	if m.BandwidthTiers[1].Period != 168*time.Hour {
		t.Errorf("expected weekly tier period 168h, got %v", m.BandwidthTiers[1].Period)
	}
}

func TestMergeLimits_BandwidthMultipleTiers_DedupByPeriod(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{
			{Bytes: 200_000_000, Period: "1h"},
			{Bytes: 10_000_000_000, Period: "168h"},
		},
	})
	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{
			{Bytes: 100_000_000, Period: "1h"},
		},
	})

	if len(m.BandwidthTiers) != 2 {
		t.Fatalf("expected 2 tiers, got %d", len(m.BandwidthTiers))
	}
	// Hourly should be the more restrictive 100MB.
	if m.BandwidthTiers[0].Bytes != 100_000_000 {
		t.Errorf("expected hourly tier 100MB (most restrictive), got %d", m.BandwidthTiers[0].Bytes)
	}
}

func TestMergeLimits_InvalidDurationIgnored(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{MaxConnDuration: "not-a-duration"})

	if m.MaxConnDuration != 0 {
		t.Errorf("expected 0 for invalid duration, got %v", m.MaxConnDuration)
	}
}

func TestMergeLimits_BandwidthInvalidPeriodSkipped(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{
			{Bytes: 1_000_000, Period: "not-a-duration"},
			{Bytes: 500_000, Period: "1h"}, // valid, should still be added
		},
	})

	if len(m.BandwidthTiers) != 1 {
		t.Fatalf("expected 1 tier (invalid period skipped), got %d", len(m.BandwidthTiers))
	}
	if m.BandwidthTiers[0].Bytes != 500_000 {
		t.Errorf("expected 500000, got %d", m.BandwidthTiers[0].Bytes)
	}
}

func TestMergeLimits_BandwidthZeroBytesSkipped(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{
			{Bytes: 0, Period: "1h"},
		},
	})

	if len(m.BandwidthTiers) != 0 {
		t.Fatalf("expected 0 tiers (zero bytes skipped), got %d", len(m.BandwidthTiers))
	}
}

func TestMergeLimits_BandwidthNegativeBytesSkipped(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{
			{Bytes: -100, Period: "1h"},
		},
	})

	if len(m.BandwidthTiers) != 0 {
		t.Fatalf("expected 0 tiers (negative bytes skipped), got %d", len(m.BandwidthTiers))
	}
}

func TestMergeLimits_BandwidthEmptyPeriodSkipped(t *testing.T) {
	var m MergedLimits

	mergeLimits(&m, &LimitsCap{
		Bandwidth: []BandwidthCap{
			{Bytes: 1_000_000, Period: ""},
		},
	})

	if len(m.BandwidthTiers) != 0 {
		t.Fatalf("expected 0 tiers (empty period skipped), got %d", len(m.BandwidthTiers))
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

	dbPerms := DatabasePermissions(result, "app_db")
	if dbPerms == nil || len(dbPerms.Permissions) != 1 || dbPerms.Permissions[0] != "SELECT ON public.users" {
		t.Errorf("unexpected perms for app_db: %v", dbPerms)
	}

	dbPerms = DatabasePermissions(result, "analytics")
	if dbPerms == nil || len(dbPerms.Permissions) != 1 || dbPerms.Permissions[0] != "SELECT ON public.events" {
		t.Errorf("unexpected perms for analytics: %v", dbPerms)
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

	dbPerms := DatabasePermissions(result, "any_database")
	if dbPerms == nil || len(dbPerms.Permissions) != 1 {
		t.Errorf("wildcard should match any database, got: %v", dbPerms)
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

	dbPerms := DatabasePermissions(result, "app_db")
	if dbPerms == nil || len(dbPerms.Permissions) != 2 {
		t.Errorf("expected exact + wildcard merged, got: %v", dbPerms)
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

	dbPerms := DatabasePermissions(result, "secret_db")
	if dbPerms != nil {
		t.Errorf("expected nil for unmatched database, got: %v", dbPerms)
	}
}

func TestDatabasePermissions_NoPGCap(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{{
			Backends: []string{"raw-tcp"},
		}},
	}

	dbPerms := DatabasePermissions(result, "any_db")
	if dbPerms != nil {
		t.Errorf("expected nil for non-PG rule, got: %v", dbPerms)
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

	dbPerms := DatabasePermissions(result, "app_db")
	if dbPerms == nil || len(dbPerms.Permissions) != 2 {
		t.Errorf("expected 2 perms from merged rules, got: %v", dbPerms)
	}
}

func TestDatabasePermissions_SQLFieldMerge(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{
			{
				Backends: []string{"pg-main"},
				PG: &PGCap{
					Databases: map[string]DBPermissions{
						"app_db": {
							Permissions: []string{"SELECT ON public.users"},
							SQL:         []string{"GRANT USAGE ON SCHEMA analytics TO {{.Role}}"},
						},
					},
				},
			},
			{
				Backends: []string{"pg-main"},
				PG: &PGCap{
					Databases: map[string]DBPermissions{
						"app_db": {
							SQL: []string{"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {{.Role}}"},
						},
						"*": {
							SQL: []string{"GRANT USAGE ON SCHEMA public TO {{.Role}}"},
						},
					},
				},
			},
		},
	}

	dbPerms := DatabasePermissions(result, "app_db")
	if dbPerms == nil {
		t.Fatal("expected non-nil perms")
	}
	if len(dbPerms.Permissions) != 1 {
		t.Errorf("expected 1 permission, got %d: %v", len(dbPerms.Permissions), dbPerms.Permissions)
	}
	if len(dbPerms.SQL) != 3 {
		t.Errorf("expected 3 SQL statements merged from exact+exact+wildcard, got %d: %v", len(dbPerms.SQL), dbPerms.SQL)
	}
}

func TestDatabasePermissions_SQLOnlyAccess(t *testing.T) {
	result := &AuthResult{
		MatchedRules: []CapRule{{
			Backends: []string{"pg-main"},
			PG: &PGCap{
				Databases: map[string]DBPermissions{
					"app_db": {
						SQL: []string{"GRANT SELECT ON public.users TO {{.Role}}"},
					},
				},
			},
		}},
	}

	dbPerms := DatabasePermissions(result, "app_db")
	if dbPerms == nil {
		t.Fatal("expected non-nil perms for SQL-only access")
	}
	if len(dbPerms.Permissions) != 0 {
		t.Errorf("expected 0 permissions, got %d", len(dbPerms.Permissions))
	}
	if len(dbPerms.SQL) != 1 || dbPerms.SQL[0] != "GRANT SELECT ON public.users TO {{.Role}}" {
		t.Errorf("unexpected SQL: %v", dbPerms.SQL)
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
