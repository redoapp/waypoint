package provision

import (
	"context"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
)

// Dialect represents the database backend type.
type Dialect int

const (
	// DialectPostgres is standard PostgreSQL.
	DialectPostgres Dialect = iota
	// DialectCockroachDB is CockroachDB.
	DialectCockroachDB
)

// dialectCache caches detected dialects per connection string.
var dialectCache struct {
	mu    sync.Mutex
	cache map[string]Dialect
}

func init() {
	dialectCache.cache = make(map[string]Dialect)
}

// detectDialect queries the database version and returns the appropriate dialect.
func detectDialect(ctx context.Context, conn *pgx.Conn, connStr string) Dialect {
	dialectCache.mu.Lock()
	if d, ok := dialectCache.cache[connStr]; ok {
		dialectCache.mu.Unlock()
		return d
	}
	dialectCache.mu.Unlock()

	var version string
	if err := conn.QueryRow(ctx, "SELECT version()").Scan(&version); err != nil {
		return DialectPostgres // default to PG on error
	}

	d := DialectPostgres
	if strings.Contains(version, "CockroachDB") {
		d = DialectCockroachDB
	}

	dialectCache.mu.Lock()
	dialectCache.cache[connStr] = d
	dialectCache.mu.Unlock()

	return d
}

// roleExistsQuery returns the appropriate SQL to check role existence.
func roleExistsQuery(d Dialect) string {
	switch d {
	case DialectCockroachDB:
		return "SELECT EXISTS(SELECT 1 FROM system.users WHERE username = $1)"
	default:
		return "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)"
	}
}
