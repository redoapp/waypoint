package proxy

import (
	"testing"

	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/querylog"
)

func level(l querylog.Level) *querylog.Level { return &l }

func TestResolveQueryLogLevel(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.QueryLogConfig
		acl  *querylog.Level
		want querylog.Level
	}{
		{
			name: "no config means off",
			cfg:  nil,
			acl:  level(querylog.LevelFull),
			want: querylog.LevelOff,
		},
		{
			name: "listener default applies when no grant mentions logging",
			cfg:  &config.QueryLogConfig{Level: "normalized", MaxLevel: "full"},
			acl:  nil,
			want: querylog.LevelNormalized,
		},
		{
			name: "grant raises within the ceiling",
			cfg:  &config.QueryLogConfig{Level: "metadata", MaxLevel: "full"},
			acl:  level(querylog.LevelFull),
			want: querylog.LevelFull,
		},
		{
			name: "ceiling clamps an over-reaching grant",
			cfg:  &config.QueryLogConfig{Level: "metadata", MaxLevel: "normalized"},
			acl:  level(querylog.LevelFull),
			want: querylog.LevelNormalized,
		},
		{
			name: "grant may also lower verbosity",
			cfg:  &config.QueryLogConfig{Level: "full", MaxLevel: "full"},
			acl:  level(querylog.LevelMetadata),
			want: querylog.LevelMetadata,
		},
		{
			name: "grant may turn logging off for a user",
			cfg:  &config.QueryLogConfig{Level: "full", MaxLevel: "full"},
			acl:  level(querylog.LevelOff),
			want: querylog.LevelOff,
		},
		{
			name: "unset max_level pins the ceiling to the default",
			cfg:  &config.QueryLogConfig{Level: "metadata"},
			acl:  level(querylog.LevelFull),
			want: querylog.LevelMetadata,
		},
		{
			name: "an off listener stays off no matter what a grant asks",
			cfg:  &config.QueryLogConfig{},
			acl:  level(querylog.LevelFull),
			want: querylog.LevelOff,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveQueryLogLevel(tt.cfg, tt.acl); got != tt.want {
				t.Errorf("resolveQueryLogLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}
