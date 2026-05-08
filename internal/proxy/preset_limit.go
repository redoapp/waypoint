package proxy

import (
	"fmt"
	"strings"

	"github.com/redoapp/waypoint/internal/auth"
)

const (
	postgresPresetLimitParam      = "waypoint_presets"
	postgresPresetLimitParamAlias = "waypoint_preset"
)

var postgresPresetRanks = map[string]int{
	"readonly":  1,
	"readwrite": 2,
	"admin":     3,
}

var postgresPresetByRank = map[int]string{
	1: "readonly",
	2: "readwrite",
	3: "admin",
}

type postgresPresetLimit struct {
	Param  string
	Raw    string
	Preset string
	Rank   int
}

func postgresPresetLimitFromStartup(params map[string]string) (*postgresPresetLimit, error) {
	raw, ok := params[postgresPresetLimitParam]
	param := postgresPresetLimitParam
	if aliasRaw, aliasOK := params[postgresPresetLimitParamAlias]; aliasOK {
		if ok && strings.TrimSpace(aliasRaw) != strings.TrimSpace(raw) {
			return nil, fmt.Errorf("%s and %s cannot both be set to different values", postgresPresetLimitParam, postgresPresetLimitParamAlias)
		}
		raw = aliasRaw
		ok = true
		param = postgresPresetLimitParamAlias
	}
	if !ok {
		return nil, nil
	}

	limit, err := parsePostgresPresetLimit(param, raw)
	if err != nil {
		return nil, err
	}
	return limit, nil
}

func parsePostgresPresetLimit(param, raw string) (*postgresPresetLimit, error) {
	parts := strings.Split(raw, ",")
	maxRank := 0
	var normalized []string
	for _, part := range parts {
		preset := strings.ToLower(strings.TrimSpace(part))
		if preset == "" {
			continue
		}
		rank, ok := postgresPresetRanks[preset]
		if !ok {
			return nil, fmt.Errorf("%s contains unknown preset %q; valid presets: readonly, readwrite, admin", param, preset)
		}
		normalized = append(normalized, preset)
		if rank > maxRank {
			maxRank = rank
		}
	}
	if maxRank == 0 {
		return nil, fmt.Errorf("%s must include at least one preset: readonly, readwrite, or admin", param)
	}

	return &postgresPresetLimit{
		Param:  param,
		Raw:    strings.Join(normalized, ","),
		Preset: postgresPresetByRank[maxRank],
		Rank:   maxRank,
	}, nil
}

func limitDBPermissionsToPostgresPreset(perms *auth.DBPermissions, limit *postgresPresetLimit) (*auth.DBPermissions, string, error) {
	if limit == nil || perms == nil {
		return perms, "", nil
	}

	authorizedRank, err := maxPostgresPresetRank(perms.Permissions)
	if err != nil {
		return nil, "", err
	}
	if authorizedRank == 0 {
		return nil, "", fmt.Errorf("no named preset permissions are authorized")
	}

	effectiveRank := authorizedRank
	if limit.Rank < effectiveRank {
		effectiveRank = limit.Rank
	}
	effectivePreset := postgresPresetByRank[effectiveRank]

	return &auth.DBPermissions{
		Permissions: []string{effectivePreset},
		Schemas:     cloneStrings(perms.Schemas),
	}, effectivePreset, nil
}

func maxPostgresPresetRank(presets []string) (int, error) {
	maxRank := 0
	for _, raw := range presets {
		preset := strings.ToLower(strings.TrimSpace(raw))
		if preset == "" {
			continue
		}
		rank, ok := postgresPresetRanks[preset]
		if !ok {
			return 0, fmt.Errorf("authorized permissions contain unknown preset %q", raw)
		}
		if rank > maxRank {
			maxRank = rank
		}
	}
	return maxRank, nil
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}
