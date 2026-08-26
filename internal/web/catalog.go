package web

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Catalog introspection for the console.
//
// Every catalog query runs on the caller's own provisioned role. That is the
// point: information_schema only exposes objects the current user has access
// to, so completion is permission-scoped without the console filtering
// anything itself. pg_catalog is not privilege-filtered, so the one query that
// needs it (foreign keys) is intersected against the information_schema table
// list afterwards.

// TableInfo is one relation the user can see, with the privileges they hold on
// it. Privileges come from has_table_privilege, which resolves through the
// group memberships provision uses to implement presets, so it is the true
// effective answer rather than an inference from the grant's preset name.
type TableInfo struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Select bool   `json:"select"`
	Insert bool   `json:"insert"`
	Update bool   `json:"update"`
	Delete bool   `json:"delete"`
}

func (t TableInfo) Qualified() string { return t.Schema + "." + t.Name }

// ForeignKey is one FK edge. Column lists are ordered to match, so composite
// keys produce correctly paired join predicates.
type ForeignKey struct {
	SrcSchema string   `json:"srcSchema"`
	SrcTable  string   `json:"srcTable"`
	SrcCols   []string `json:"srcCols"`
	TgtSchema string   `json:"tgtSchema"`
	TgtTable  string   `json:"tgtTable"`
	TgtCols   []string `json:"tgtCols"`
}

// ColumnInfo is one column, fetched lazily per table.
type ColumnInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	NotNull  bool   `json:"notNull"`
	Default  string `json:"default,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Position int    `json:"position"`
}

// Catalog is the eager payload: relations and the FK graph. Columns are
// deliberately excluded — they are the part that does not fit in a browser for
// a large database, so they load per table on demand.
type Catalog struct {
	Tables      []TableInfo  `json:"tables"`
	ForeignKeys []ForeignKey `json:"foreignKeys"`
	Schemas     []string     `json:"schemas"`
}

// tableByName indexes the catalog for lookups by qualified and bare name.
func (c *Catalog) lookup(schema, name string) (TableInfo, bool) {
	for _, t := range c.Tables {
		if !strings.EqualFold(t.Name, name) {
			continue
		}
		if schema == "" || strings.EqualFold(t.Schema, schema) {
			return t, true
		}
	}
	return TableInfo{}, false
}

// fksFor returns FK edges touching the given table in either direction.
func (c *Catalog) fksFor(schema, name string) []ForeignKey {
	var out []ForeignKey
	for _, fk := range c.ForeignKeys {
		if strings.EqualFold(fk.SrcTable, name) && (schema == "" || strings.EqualFold(fk.SrcSchema, schema)) {
			out = append(out, fk)
			continue
		}
		if strings.EqualFold(fk.TgtTable, name) && (schema == "" || strings.EqualFold(fk.TgtSchema, schema)) {
			out = append(out, fk)
		}
	}
	return out
}

const tablesQuery = `
SELECT t.table_schema, t.table_name, t.table_type
FROM information_schema.tables t
WHERE t.table_schema NOT IN ('pg_catalog', 'information_schema')
  AND t.table_type IN ('BASE TABLE', 'VIEW')
ORDER BY t.table_schema, t.table_name
`

// privsQuery batches the four privilege probes over the visible relations.
// to_regclass returns NULL rather than erroring for anything that vanished
// between the two queries.
const privsQuery = `
SELECT c.qname,
       COALESCE(has_table_privilege(c.qname, 'SELECT'), false),
       COALESCE(has_table_privilege(c.qname, 'INSERT'), false),
       COALESCE(has_table_privilege(c.qname, 'UPDATE'), false),
       COALESCE(has_table_privilege(c.qname, 'DELETE'), false)
FROM unnest($1::text[]) AS c(qname)
WHERE to_regclass(c.qname) IS NOT NULL
`

const fkQuery = `
SELECT src_ns.nspname, src.relname,
       (SELECT array_agg(a.attname ORDER BY x.ord)
          FROM unnest(c.conkey) WITH ORDINALITY x(att, ord)
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = x.att),
       tgt_ns.nspname, tgt.relname,
       (SELECT array_agg(a.attname ORDER BY x.ord)
          FROM unnest(c.confkey) WITH ORDINALITY x(att, ord)
          JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = x.att)
FROM pg_constraint c
JOIN pg_class src ON src.oid = c.conrelid
JOIN pg_namespace src_ns ON src_ns.oid = src.relnamespace
JOIN pg_class tgt ON tgt.oid = c.confrelid
JOIN pg_namespace tgt_ns ON tgt_ns.oid = tgt.relnamespace
WHERE c.contype = 'f'
  AND src_ns.nspname NOT IN ('pg_catalog', 'information_schema')
`

const columnsQuery = `
SELECT a.attname,
       format_type(a.atttypid, a.atttypmod),
       a.attnotnull,
       COALESCE(pg_get_expr(d.adbin, d.adrelid), ''),
       COALESCE(col_description(a.attrelid, a.attnum), ''),
       a.attnum
FROM pg_attribute a
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attrelid = to_regclass($1)
  AND a.attnum > 0
  AND NOT a.attisdropped
ORDER BY a.attnum
`

// fetchCatalog reads relations, privileges, and the FK graph.
func fetchCatalog(ctx context.Context, pool *pgxpool.Pool) (*Catalog, error) {
	cat := &Catalog{Tables: []TableInfo{}, ForeignKeys: []ForeignKey{}, Schemas: []string{}}

	rows, err := pool.Query(ctx, tablesQuery)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	visible := map[string]bool{}
	schemaSeen := map[string]bool{}
	for rows.Next() {
		var schema, name, typ string
		if err := rows.Scan(&schema, &name, &typ); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan table: %w", err)
		}
		kind := "table"
		if typ == "VIEW" {
			kind = "view"
		}
		cat.Tables = append(cat.Tables, TableInfo{Schema: schema, Name: name, Kind: kind})
		visible[strings.ToLower(schema+"."+name)] = true
		if !schemaSeen[schema] {
			schemaSeen[schema] = true
			cat.Schemas = append(cat.Schemas, schema)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	sort.Strings(cat.Schemas)

	if len(cat.Tables) == 0 {
		return cat, nil
	}

	// Privileges, batched over every visible relation.
	quoted := make([]string, 0, len(cat.Tables))
	for _, t := range cat.Tables {
		quoted = append(quoted, quoteQualified(t.Schema, t.Name))
	}
	privRows, err := pool.Query(ctx, privsQuery, quoted)
	if err != nil {
		return nil, fmt.Errorf("table privileges: %w", err)
	}
	privs := make(map[string][4]bool, len(cat.Tables))
	for privRows.Next() {
		var qname string
		var sel, ins, upd, del bool
		if err := privRows.Scan(&qname, &sel, &ins, &upd, &del); err != nil {
			privRows.Close()
			return nil, fmt.Errorf("scan privileges: %w", err)
		}
		privs[qname] = [4]bool{sel, ins, upd, del}
	}
	privRows.Close()
	if err := privRows.Err(); err != nil {
		return nil, fmt.Errorf("table privileges: %w", err)
	}
	for i := range cat.Tables {
		p, ok := privs[quoteQualified(cat.Tables[i].Schema, cat.Tables[i].Name)]
		if !ok {
			continue
		}
		cat.Tables[i].Select, cat.Tables[i].Insert, cat.Tables[i].Update, cat.Tables[i].Delete = p[0], p[1], p[2], p[3]
	}

	// Foreign keys. pg_catalog is not privilege-filtered, so drop any edge
	// whose endpoints the user cannot already see via information_schema.
	fkRows, err := pool.Query(ctx, fkQuery)
	if err != nil {
		// A restricted role can still be denied pg_constraint. Join
		// assistance degrades, completion does not.
		return cat, nil
	}
	for fkRows.Next() {
		var fk ForeignKey
		if err := fkRows.Scan(&fk.SrcSchema, &fk.SrcTable, &fk.SrcCols, &fk.TgtSchema, &fk.TgtTable, &fk.TgtCols); err != nil {
			fkRows.Close()
			return cat, nil
		}
		if !visible[strings.ToLower(fk.SrcSchema+"."+fk.SrcTable)] {
			continue
		}
		if !visible[strings.ToLower(fk.TgtSchema+"."+fk.TgtTable)] {
			continue
		}
		cat.ForeignKeys = append(cat.ForeignKeys, fk)
	}
	fkRows.Close()

	return cat, nil
}

func fetchColumns(ctx context.Context, pool *pgxpool.Pool, schema, table string) ([]ColumnInfo, error) {
	rows, err := pool.Query(ctx, columnsQuery, quoteQualified(schema, table))
	if err != nil {
		return nil, fmt.Errorf("list columns: %w", err)
	}
	defer rows.Close()
	cols := []ColumnInfo{}
	for rows.Next() {
		var c ColumnInfo
		if err := rows.Scan(&c.Name, &c.Type, &c.NotNull, &c.Default, &c.Comment, &c.Position); err != nil {
			return nil, fmt.Errorf("scan column: %w", err)
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// quoteQualified renders schema.table for to_regclass / has_table_privilege,
// which take a text name and parse it, so identifiers need real quoting.
func quoteQualified(schema, table string) string {
	return quoteIdent(schema) + "." + quoteIdent(table)
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// catalogCache memoizes catalog and column reads per (database, role).
//
// This is a cache, never session state: entries are reconstructible from the
// database at any time, and dropping one costs a round trip rather than
// correctness. That distinction is what keeps the console stateless.
type catalogCache struct {
	ttl sync.Map // string -> *catalogEntry
	dur time.Duration
}

type catalogEntry struct {
	mu      sync.Mutex
	cat     *Catalog
	cols    map[string][]ColumnInfo
	fetched time.Time
}

func newCatalogCache(d time.Duration) *catalogCache {
	if d <= 0 {
		d = time.Minute
	}
	return &catalogCache{dur: d}
}

func (c *catalogCache) entry(key string) *catalogEntry {
	v, _ := c.ttl.LoadOrStore(key, &catalogEntry{cols: map[string][]ColumnInfo{}})
	return v.(*catalogEntry)
}

// Get returns the catalog for key, refreshing it when the TTL has passed.
func (c *catalogCache) Get(ctx context.Context, key string, pool *pgxpool.Pool) (*Catalog, error) {
	e := c.entry(key)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cat != nil && time.Since(e.fetched) < c.dur {
		return e.cat, nil
	}
	cat, err := fetchCatalog(ctx, pool)
	if err != nil {
		if e.cat != nil {
			// Serve the stale copy rather than breaking the editor.
			return e.cat, nil
		}
		return nil, err
	}
	e.cat = cat
	e.cols = map[string][]ColumnInfo{}
	e.fetched = time.Now()
	return cat, nil
}

// Columns returns one relation's columns, memoized alongside its catalog.
func (c *catalogCache) Columns(ctx context.Context, key string, pool *pgxpool.Pool, schema, table string) ([]ColumnInfo, error) {
	e := c.entry(key)
	ck := strings.ToLower(schema + "." + table)
	e.mu.Lock()
	if cols, ok := e.cols[ck]; ok {
		e.mu.Unlock()
		return cols, nil
	}
	e.mu.Unlock()

	cols, err := fetchColumns(ctx, pool, schema, table)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.cols[ck] = cols
	e.mu.Unlock()
	return cols, nil
}

// Invalidate drops a cached catalog, used by the console's refresh action.
func (c *catalogCache) Invalidate(key string) {
	c.ttl.Delete(key)
}
