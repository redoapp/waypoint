package proxy

import (
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/querylog"
)

// resolveQueryLogLevel works out how much query detail to log for one
// connection.
//
// The listener config supplies the default and the ceiling; an ACL capability
// grant may move the user within that range but never past the ceiling. So the
// operator owns the upper bound on how much statement content can reach the
// logs, while the tailnet admin decides where a given user sits beneath it.
//
// A nil aclLevel means no matched grant mentioned logging, in which case the
// listener default applies unchanged.
func resolveQueryLogLevel(cfg *config.QueryLogConfig, aclLevel *querylog.Level) querylog.Level {
	if cfg == nil {
		return querylog.LevelOff
	}

	// Both values were validated at config load, so a parse failure here
	// would mean a programming error rather than bad input. Fail closed.
	fallback, err := querylog.ParseLevel(cfg.EffectiveLevel())
	if err != nil {
		return querylog.LevelOff
	}
	ceiling, err := querylog.ParseLevel(cfg.EffectiveMaxLevel())
	if err != nil {
		return querylog.LevelOff
	}

	want := fallback
	if aclLevel != nil {
		want = *aclLevel
	}
	return querylog.Clamp(want, ceiling)
}
