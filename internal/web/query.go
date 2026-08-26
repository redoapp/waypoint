package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/redoapp/waypoint/internal/querylog"
)

// Query execution.
//
// Results stream as newline-delimited JSON. The first frame carries the
// backend PID, which is what makes cancellation work without server-side
// session state: the browser learns the PID before any rows arrive, and any
// instance can later cancel that backend knowing only the PID. Nothing about a
// running query is held in this process's memory.

type queryRequest struct {
	SQL       string `json:"sql"`
	CursorPos int    `json:"cursorPos"`
	Database  string `json:"database"`
	// RunAll executes the whole buffer instead of the statement under the
	// caret. The console's "run all" action sets it.
	RunAll bool `json:"runAll"`
}

type cancelRequest struct {
	PID      int32  `json:"pid"`
	Database string `json:"database"`
}

// ndjson writes one frame per line and flushes, so the browser sees the PID
// frame immediately rather than when the response completes.
type ndjson struct {
	w   http.ResponseWriter
	f   http.Flusher
	enc *json.Encoder
}

func newNDJSON(w http.ResponseWriter) *ndjson {
	f, _ := w.(http.Flusher)
	return &ndjson{w: w, f: f, enc: json.NewEncoder(w)}
}

func (n *ndjson) send(v any) error {
	if err := n.enc.Encode(v); err != nil {
		return err
	}
	if n.f != nil {
		n.f.Flush()
	}
	return nil
}

type frameBegin struct {
	Type      string `json:"type"`
	PID       int32  `json:"pid"`
	Database  string `json:"database"`
	Statement string `json:"statement"`
}

type frameColumns struct {
	Type    string       `json:"type"`
	Columns []columnMeta `json:"columns"`
}

type columnMeta struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type frameRows struct {
	Type string              `json:"type"`
	Rows [][]json.RawMessage `json:"rows"`
}

type frameEnd struct {
	Type       string `json:"type"`
	RowCount   int    `json:"rowCount"`
	Truncated  bool   `json:"truncated"`
	DurationMS int64  `json:"durationMs"`
	Command    string `json:"command"`
}

type frameError struct {
	Type     string `json:"type"`
	Message  string `json:"message"`
	Code     string `json:"code,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Hint     string `json:"hint,omitempty"`
	Position int32  `json:"position,omitempty"`
}

const rowBatch = 200

// execute runs one statement and streams its result.
func (s *Server) execute(
	ctx context.Context,
	out *ndjson,
	pool *pgxpool.Pool,
	sess *session,
	database string,
	stmt string,
) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return out.send(frameError{Type: "error", Message: "acquire connection: " + err.Error()})
	}
	defer conn.Release()

	// The PID must come from the same physical connection the query runs on.
	var pid int32
	if err := conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		return out.send(frameError{Type: "error", Message: "backend pid: " + err.Error()})
	}
	if err := out.send(frameBegin{Type: "begin", PID: pid, Database: database, Statement: stmt}); err != nil {
		return err
	}

	start := time.Now()
	rows, err := conn.Query(ctx, stmt)
	if err != nil {
		s.logQuery(ctx, sess, database, stmt, 0, time.Since(start), err)
		return out.send(pgErrorFrame(err))
	}

	fds := rows.FieldDescriptions()
	cols := s.describeColumns(ctx, pool, conn, database, fds)
	if len(cols) > 0 {
		if err := out.send(frameColumns{Type: "columns", Columns: cols}); err != nil {
			rows.Close()
			return err
		}
	}

	maxRows := s.webCfg.EffectiveMaxRows()
	batch := make([][]json.RawMessage, 0, rowBatch)
	count := 0
	truncated := false

	for rows.Next() {
		if count >= maxRows {
			truncated = true
			break
		}
		vals, err := rows.Values()
		if err != nil {
			rows.Close()
			s.logQuery(ctx, sess, database, stmt, int64(count), time.Since(start), err)
			return out.send(pgErrorFrame(err))
		}
		row := make([]json.RawMessage, len(vals))
		for i, v := range vals {
			row[i] = encodeValue(v)
		}
		batch = append(batch, row)
		count++
		if len(batch) >= rowBatch {
			if err := out.send(frameRows{Type: "rows", Rows: batch}); err != nil {
				rows.Close()
				return err
			}
			batch = batch[:0]
		}
	}
	if len(batch) > 0 {
		if err := out.send(frameRows{Type: "rows", Rows: batch}); err != nil {
			rows.Close()
			return err
		}
	}

	// Draining a truncated result keeps the connection reusable.
	if truncated {
		for rows.Next() {
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logQuery(ctx, sess, database, stmt, int64(count), time.Since(start), err)
		return out.send(pgErrorFrame(err))
	}

	tag := rows.CommandTag()
	elapsed := time.Since(start)
	s.logQuery(ctx, sess, database, stmt, int64(count), elapsed, nil)

	return out.send(frameEnd{
		Type:       "end",
		RowCount:   count,
		Truncated:  truncated,
		DurationMS: elapsed.Milliseconds(),
		Command:    tag.String(),
	})
}

// cancel stops a running statement. Verified behaviour: a non-superuser can
// cancel its own backend from a different connection, and the cancelled
// connection stays usable afterwards, so it goes back in the pool.
func (s *Server) cancel(ctx context.Context, pool *pgxpool.Pool, pgUser string, pid int32) error {
	// Confirm the target belongs to this user's role before signalling it.
	// Postgres enforces this too, but checking first turns a permission error
	// into a clear message and stops the endpoint being used to probe PIDs.
	var owner string
	err := pool.QueryRow(ctx, "SELECT usename FROM pg_stat_activity WHERE pid = $1", pid).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("no such backend")
	}
	if err != nil {
		return fmt.Errorf("look up backend: %w", err)
	}
	if owner != pgUser {
		return fmt.Errorf("backend does not belong to this session")
	}

	var ok bool
	if err := pool.QueryRow(ctx, "SELECT pg_cancel_backend($1)", pid).Scan(&ok); err != nil {
		return fmt.Errorf("cancel: %w", err)
	}
	if !ok {
		return fmt.Errorf("backend did not accept the cancel request")
	}
	return nil
}

// logQuery emits the statement into the same audit stream the wire proxies
// feed, so a query run in the browser is indistinguishable from one run
// through psql as far as the audit log is concerned.
func (s *Server) logQuery(ctx context.Context, sess *session, database, stmt string, rows int64, dur time.Duration, execErr error) {
	if s.queryLog == nil {
		return
	}
	level := resolveQueryLogLevel(s.queryLogCfg, sess.Auth.QueryLog)
	if level <= querylog.LevelOff {
		return
	}
	ev := &querylog.Event{
		ConnID:            sess.ReqID,
		Listener:          s.name,
		User:              sess.Auth.LoginName,
		Mode:              querylog.ModePostgres,
		Database:          database,
		Level:             level,
		RawStatement:      stmt,
		Rows:              rows,
		ReqBytes:          int64(len(stmt)),
		Duration:          dur,
		MaxStatementBytes: s.queryLogCfg.EffectiveMaxStatementBytes(),
	}
	if execErr != nil {
		ev.Err = execErr.Error()
	}
	s.queryLog.Log(ev)
}

// describeColumns names each result column's type.
//
// pgx's type map knows the built-in OIDs, but a user-defined type — an enum,
// a domain, a composite — is not in it, and a column headed "oid:16630" is
// useless to the person reading the grid. Unknown OIDs are resolved against
// pg_type in a single batched query and memoized, since type OIDs are stable
// for the life of a database.
// It takes the pool as well as the connection because the lookup has to run on
// a different connection: the caller's result rows are still open on conn, and
// pgx rejects a second query on a busy connection.
func (s *Server) describeColumns(ctx context.Context, pool *pgxpool.Pool, conn *pgxpool.Conn, database string, fds []pgconn.FieldDescription) []columnMeta {
	tm := conn.Conn().TypeMap()
	cols := make([]columnMeta, 0, len(fds))
	var unknown []int64

	for _, fd := range fds {
		if dt, ok := tm.TypeForOID(fd.DataTypeOID); ok {
			cols = append(cols, columnMeta{Name: fd.Name, Type: dt.Name})
			continue
		}
		if name, ok := s.typeNames.Load(typeKey(database, fd.DataTypeOID)); ok {
			cols = append(cols, columnMeta{Name: fd.Name, Type: name.(string)})
			continue
		}
		unknown = append(unknown, int64(fd.DataTypeOID))
		cols = append(cols, columnMeta{Name: fd.Name, Type: fmt.Sprintf("oid:%d", fd.DataTypeOID)})
	}

	if len(unknown) == 0 {
		return cols
	}

	// Compare as bigint: pgx has no array encoder for the oid type, so the
	// OIDs travel as int8[] and are cast on the server side.
	rows, err := pool.Query(ctx,
		`SELECT oid::bigint, typname FROM pg_type WHERE oid::bigint = ANY($1)`, unknown)
	if err != nil {
		// A type name is a nicety, so this must never fail the query — but it
		// is logged, because a silent fallback to "oid:16630" in the grid is
		// exactly the kind of thing nobody reports and nobody fixes.
		s.logger.DebugContext(ctx, "could not resolve column type names", "error", err)
		return cols
	}
	defer rows.Close()

	resolved := make(map[uint32]string, len(unknown))
	for rows.Next() {
		var oid int64
		var name string
		if err := rows.Scan(&oid, &name); err != nil {
			s.logger.DebugContext(ctx, "could not scan column type name", "error", err)
			return cols
		}
		resolved[uint32(oid)] = name
		s.typeNames.Store(typeKey(database, uint32(oid)), name)
	}

	for i, fd := range fds {
		if name, ok := resolved[fd.DataTypeOID]; ok {
			cols[i].Type = name
		}
	}
	return cols
}

func typeKey(database string, oid uint32) string {
	return database + "\x00" + strconv.FormatUint(uint64(oid), 10)
}

func pgErrorFrame(err error) frameError {
	f := frameError{Type: "error", Message: err.Error()}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		f.Message = pe.Message
		f.Code = pe.Code
		f.Detail = pe.Detail
		f.Hint = pe.Hint
		f.Position = pe.Position
	}
	return f
}

// encodeValue renders a scanned value as JSON, falling back to the value's
// string form for anything the encoder cannot represent. A console must never
// fail to display a row because of an exotic column type.
func encodeValue(v any) json.RawMessage {
	if v == nil {
		return json.RawMessage("null")
	}
	switch t := v.(type) {
	case []byte:
		if isPrintable(t) {
			return mustMarshal(string(t))
		}
		return mustMarshal(fmt.Sprintf("\\x%x", t))
	case time.Time:
		return mustMarshal(t.Format(time.RFC3339Nano))
	}
	if b, err := json.Marshal(v); err == nil {
		return b
	}
	return mustMarshal(fmt.Sprintf("%v", v))
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return b
}

// isPrintable reports whether a bytea value can be shown as text rather than
// a hex escape.
func isPrintable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r == utf8.RuneError || (r < 0x20 && r != '\n' && r != '\r' && r != '\t') {
			return false
		}
	}
	return true
}
