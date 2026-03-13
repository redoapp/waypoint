package provision

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redoapp/waypoint/internal/restrict"
)

// Cleaner periodically drops idle dynamic PG users.
type Cleaner struct {
	adminConnStr string
	userPrefix   string
	ttl          time.Duration
	store        *restrict.RedisStore
	logger       *slog.Logger
}

// NewCleaner creates a new user cleanup worker.
func NewCleaner(adminUser, adminPassword, adminDatabase, backend, userPrefix string, ttl time.Duration, store *restrict.RedisStore, logger *slog.Logger) *Cleaner {
	connStr := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable",
		adminUser, adminPassword, backend, adminDatabase)
	if userPrefix == "" {
		userPrefix = "wp_"
	}
	return &Cleaner{
		adminConnStr: connStr,
		userPrefix:   userPrefix,
		ttl:          ttl,
		store:        store,
		logger:       logger,
	}
}

// Run starts the cleanup loop. Blocks until ctx is cancelled.
func (c *Cleaner) Run(ctx context.Context) {
	// Run immediately on start, then every ttl/4.
	interval := c.ttl / 4
	if interval < time.Minute {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		c.cleanup(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Cleaner) cleanup(ctx context.Context) {
	conn, err := pgx.Connect(ctx, c.adminConnStr)
	if err != nil {
		c.logger.Error("cleanup: admin connect failed", "error", err)
		return
	}
	defer conn.Close(ctx)

	// Find all roles matching our prefix.
	rows, err := conn.Query(ctx,
		"SELECT rolname FROM pg_roles WHERE rolname LIKE $1",
		c.userPrefix+"%",
	)
	if err != nil {
		c.logger.Error("cleanup: query roles failed", "error", err)
		return
	}
	// Collect roles first to avoid pgx implicit result set closure.
	var roles []string
	for rows.Next() {
		var rolname string
		if err := rows.Scan(&rolname); err != nil {
			continue
		}
		roles = append(roles, rolname)
	}
	rows.Close()

	now := time.Now()
	var dropped int

	for _, rolname := range roles {
		lastUsed, err := c.store.GetLastUsed(ctx, rolname)
		if err != nil {
			c.logger.Warn("cleanup: get last used failed", "role", rolname, "error", err)
			continue
		}

		// If never recorded or older than TTL, drop.
		if !lastUsed.IsZero() && now.Sub(lastUsed) < c.ttl {
			continue
		}

		// Check for active connections before dropping.
		var activeConns int
		err = conn.QueryRow(ctx,
			"SELECT count(*) FROM pg_stat_activity WHERE usename = $1",
			rolname,
		).Scan(&activeConns)
		if err != nil || activeConns > 0 {
			continue
		}

		if err := dropRole(ctx, conn, rolname); err != nil {
			c.logger.Warn("cleanup: drop role failed", "role", rolname, "error", err)
			continue
		}

		dropped++
		c.logger.Info("cleanup: dropped idle role", "role", rolname)
	}

	if dropped > 0 {
		c.logger.Info("cleanup complete", "dropped", dropped)
	}
}

// dropRole revokes all privileges and drops the role.
func dropRole(ctx context.Context, conn *pgx.Conn, rolname string) error {
	sanitized := pgx.Identifier{rolname}.Sanitize()

	// Revoke all privileges on all databases.
	// Collect database names first to avoid pgx implicit result set closure.
	var databases []string
	rows, err := conn.Query(ctx,
		"SELECT datname FROM pg_database WHERE datistemplate = false")
	if err == nil {
		for rows.Next() {
			var dbname string
			if err := rows.Scan(&dbname); err != nil {
				continue
			}
			databases = append(databases, dbname)
		}
		rows.Close()
	}
	for _, dbname := range databases {
		conn.Exec(ctx, fmt.Sprintf(
			"REVOKE ALL PRIVILEGES ON DATABASE %s FROM %s",
			pgx.Identifier{dbname}.Sanitize(), sanitized))
	}

	// Reassign owned objects and drop owned.
	stmts := []string{
		fmt.Sprintf("REASSIGN OWNED BY %s TO CURRENT_USER", sanitized),
		fmt.Sprintf("DROP OWNED BY %s", sanitized),
		fmt.Sprintf("DROP ROLE IF EXISTS %s", sanitized),
	}

	for _, stmt := range stmts {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			if !strings.Contains(err.Error(), "does not exist") {
				return fmt.Errorf("%s: %w", stmt, err)
			}
		}
	}

	return nil
}
