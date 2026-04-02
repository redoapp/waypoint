package logging

import (
	"fmt"
	"log/slog"
	"strings"
)

// ParseLevel converts a case-insensitive level name to slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", s)
	}
}

// ResolveLevel determines the effective log level. The environment variable
// (envVal) takes precedence over the config file value (configVal). If neither
// is set, defaultLevel is returned.
func ResolveLevel(envVal, configVal string, defaultLevel slog.Level) (slog.Level, error) {
	if envVal != "" {
		return ParseLevel(envVal)
	}
	if configVal != "" {
		return ParseLevel(configVal)
	}
	return defaultLevel, nil
}
