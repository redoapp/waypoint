package querylog

import (
	"log/slog"
	"time"
)

// Mode names the protocol a record came from.
const (
	ModePostgres = "postgres"
	ModeMongoDB  = "mongodb"
)

// Event is one logged statement. It is assembled by a tap on the relay path
// and handed to an Emitter, which does the parsing and formatting off the hot
// path.
//
// Taps fill in RawStatement and Level; the Emitter derives Op/Kind/Tables and
// the statement text from them. Mongo taps fill in the command fields directly,
// since there is no SQL to parse.
type Event struct {
	// Connection identity, copied from the proxy's per-connection logger.
	ConnID   string
	Listener string
	User     string
	Mode     string
	Database string

	// Level the record was captured at, already clamped by the listener
	// ceiling. The Emitter uses it to decide how much text to include.
	Level Level

	// RawStatement is the SQL as the client sent it. Postgres only.
	RawStatement string

	// Pre-derived command details. MongoDB fills these in; Postgres leaves
	// them empty and lets the Emitter derive them from RawStatement.
	Op          string
	Kind        string
	Collection  string
	Tables      []string
	WriteTarget string
	Fingerprint string
	Statement   string

	// Params holds bind parameter values, included only at LevelFull.
	Params []string

	// MaxStatementBytes caps the logged statement text for this listener.
	// Zero means DefaultMaxStatementBytes.
	MaxStatementBytes int

	// Request and response metadata.
	ReqBytes   int64
	Rows       int64
	RespBytes  int64
	Duration   time.Duration
	Err        string
	Truncated  bool
	ParseError bool
}

// attrs renders the event as slog attributes, omitting empty fields so the
// records stay readable at metadata level.
func (e *Event) attrs(maxStatementBytes int) []slog.Attr {
	a := make([]slog.Attr, 0, 18)
	a = append(a, slog.String("component", "querylog"))

	addStr := func(k, v string) {
		if v != "" {
			a = append(a, slog.String(k, v))
		}
	}

	addStr("conn_id", e.ConnID)
	addStr("listener", e.Listener)
	addStr("user", e.User)
	addStr("mode", e.Mode)
	addStr("database", e.Database)
	addStr("collection", e.Collection)
	addStr("op", e.Op)
	addStr("kind", e.Kind)
	addStr("write_target", e.WriteTarget)
	addStr("fingerprint", e.Fingerprint)

	if len(e.Tables) > 0 {
		a = append(a, slog.Any("tables", e.Tables))
	}

	if e.Statement != "" {
		stmt, truncated := truncate(e.Statement, maxStatementBytes)
		a = append(a, slog.String("statement", stmt))
		if truncated {
			e.Truncated = true
		}
	}
	if len(e.Params) > 0 {
		a = append(a, slog.Any("params", e.Params))
	}

	if e.ReqBytes > 0 {
		a = append(a, slog.Int64("req_bytes", e.ReqBytes))
	}
	a = append(a,
		slog.Int64("rows", e.Rows),
		slog.Int64("resp_bytes", e.RespBytes),
		slog.Float64("duration_ms", float64(e.Duration.Microseconds())/1000.0),
	)

	addStr("error", e.Err)
	if e.ParseError {
		a = append(a, slog.Bool("parse_error", true))
	}
	if e.Truncated {
		a = append(a, slog.Bool("truncated", true))
	}

	return a
}

// truncate cuts s to at most max bytes without splitting a UTF-8 rune.
func truncate(s string, max int) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	cut := max
	// Back off to a rune boundary: continuation bytes are 10xxxxxx.
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut], true
}
