// Package querylog captures per-statement activity from the Postgres and
// MongoDB proxies and emits it as structured slog records.
//
// The package is deliberately a leaf: it depends on the wire-protocol helpers
// and the SQL parser, but never on internal/proxy or internal/auth, so both of
// those can depend on it without a cycle.
package querylog

import (
	"fmt"
	"strings"
)

// Level controls how much detail a query log record carries.
type Level int

const (
	// LevelOff disables query logging entirely. No tap is installed, so the
	// relay path is byte-identical to a build without this feature.
	LevelOff Level = iota

	// LevelMetadata emits the statement shape — verb, kind, tables,
	// fingerprint — plus response counters, but no statement text.
	//
	// The one exception is a statement the parser rejects: those carry their
	// raw text so an unparseable statement is never silently dropped. See
	// Analyze.
	LevelMetadata

	// LevelNormalized adds the statement text with constants elided.
	LevelNormalized

	// LevelFull adds the verbatim statement text and bind parameter values.
	// This puts row data into the log pipeline.
	LevelFull
)

// ParseLevel converts a case-insensitive level name to a Level.
// It mirrors logging.ParseLevel so config and ACL values behave alike.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "none", "disabled":
		return LevelOff, nil
	case "metadata", "meta":
		return LevelMetadata, nil
	case "normalized", "normalised":
		return LevelNormalized, nil
	case "full":
		return LevelFull, nil
	default:
		return 0, fmt.Errorf("unknown query log level %q", s)
	}
}

func (l Level) String() string {
	switch l {
	case LevelOff:
		return "off"
	case LevelMetadata:
		return "metadata"
	case LevelNormalized:
		return "normalized"
	case LevelFull:
		return "full"
	default:
		return fmt.Sprintf("Level(%d)", int(l))
	}
}

// Clamp returns want capped at ceiling. It is how an ACL-supplied level is
// held to the limit the operator configured on the listener: a grant may raise
// verbosity, but never past what the listener permits.
func Clamp(want, ceiling Level) Level {
	if want > ceiling {
		return ceiling
	}
	return want
}
