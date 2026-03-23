package testutil

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	redisOnce   sync.Once
	redisClient *redis.Client
	redisErr    error

	pgOnce    sync.Once
	pgConnStr string
	pgBackend string
	pgErr     error

	crdbOnce    sync.Once
	crdbConnStr string
	crdbBackend string
	crdbErr     error
)

// RedisClient starts a shared Redis 7-alpine container (once per test binary)
// and returns a connected client. The client is closed when the test finishes.
func RedisClient(t *testing.T) *redis.Client {
	t.Helper()

	redisOnce.Do(func() {
		ctx := context.Background()
		container, err := tcredis.Run(ctx, "redis:7-alpine")
		if err != nil {
			redisErr = fmt.Errorf("start redis container: %w", err)
			return
		}

		connStr, err := container.ConnectionString(ctx)
		if err != nil {
			redisErr = fmt.Errorf("redis connection string: %w", err)
			return
		}

		opts, err := redis.ParseURL(connStr)
		if err != nil {
			redisErr = fmt.Errorf("parse redis url: %w", err)
			return
		}

		redisClient = redis.NewClient(opts)
		if err := redisClient.Ping(ctx).Err(); err != nil {
			redisErr = fmt.Errorf("redis ping: %w", err)
			return
		}
	})

	if redisErr != nil {
		t.Fatalf("redis container: %v", redisErr)
	}

	// Flush before each test for isolation.
	if err := redisClient.FlushAll(context.Background()).Err(); err != nil {
		t.Fatalf("redis flushall: %v", err)
	}

	return redisClient
}

// RedisClientRaw returns the shared Redis client without flushing.
// Use this when you need to manipulate Redis state mid-test without
// losing data set by prior operations in the same test.
func RedisClientRaw(t *testing.T) *redis.Client {
	t.Helper()
	if redisErr != nil {
		t.Fatalf("redis container: %v", redisErr)
	}
	if redisClient == nil {
		t.Fatal("RedisClientRaw called before RedisClient")
	}
	return redisClient
}

// PostgresBackend starts a shared PostgreSQL 16-alpine container (once per test binary)
// and returns the admin connection string and host:port backend address.
func PostgresBackend(t *testing.T) (connStr string, backend string) {
	t.Helper()

	pgOnce.Do(func() {
		ctx := context.Background()
		container, err := tcpostgres.Run(ctx,
			"postgres:16-alpine",
			tcpostgres.WithDatabase("waypoint_test"),
			tcpostgres.WithUsername("admin"),
			tcpostgres.WithPassword("adminpass"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(2*time.Minute),
			),
		)
		if err != nil {
			pgErr = fmt.Errorf("start postgres container: %w", err)
			return
		}

		cs, err := container.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			pgErr = fmt.Errorf("postgres connection string: %w", err)
			return
		}

		host, err := container.Host(ctx)
		if err != nil {
			pgErr = fmt.Errorf("postgres host: %w", err)
			return
		}

		port, err := container.MappedPort(ctx, "5432/tcp")
		if err != nil {
			pgErr = fmt.Errorf("postgres port: %w", err)
			return
		}

		// Verify connection works with retries.
		var conn *pgx.Conn
		for i := 0; i < 10; i++ {
			conn, err = pgx.Connect(ctx, cs)
			if err == nil {
				conn.Close(ctx)
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			pgErr = fmt.Errorf("postgres connect after retries: %w", err)
			return
		}

		pgConnStr = cs
		pgBackend = fmt.Sprintf("%s:%s", host, port.Port())
	})

	if pgErr != nil {
		t.Fatalf("postgres container: %v", pgErr)
	}

	return pgConnStr, pgBackend
}

// CockroachDBBackend starts a shared single-node CockroachDB container (once per test binary)
// and returns the admin connection string and host:port backend address.
func CockroachDBBackend(t *testing.T) (connStr string, backend string) {
	t.Helper()

	crdbOnce.Do(func() {
		ctx := context.Background()
		container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "cockroachdb/cockroach:latest-v24.3",
				ExposedPorts: []string{"26257/tcp"},
				Cmd:          []string{"start-single-node", "--insecure", "--store=type=mem,size=256MiB"},
				WaitingFor: wait.ForLog("CockroachDB node starting at").
					WithStartupTimeout(2 * time.Minute),
			},
			Started: true,
		})
		if err != nil {
			crdbErr = fmt.Errorf("start cockroachdb container: %w", err)
			return
		}

		host, err := container.Host(ctx)
		if err != nil {
			crdbErr = fmt.Errorf("cockroachdb host: %w", err)
			return
		}

		port, err := container.MappedPort(ctx, "26257/tcp")
		if err != nil {
			crdbErr = fmt.Errorf("cockroachdb port: %w", err)
			return
		}

		cs := fmt.Sprintf("postgres://root@%s:%s/defaultdb?sslmode=disable", host, port.Port())

		// Create a test database and admin user with password.
		var conn *pgx.Conn
		for i := 0; i < 10; i++ {
			conn, err = pgx.Connect(ctx, cs)
			if err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			crdbErr = fmt.Errorf("cockroachdb connect after retries: %w", err)
			return
		}

		// Create database and admin role.
		stmts := []string{
			"CREATE DATABASE IF NOT EXISTS waypoint_test",
			"CREATE USER IF NOT EXISTS admin WITH PASSWORD 'adminpass'",
			"GRANT admin TO root",
			"GRANT ALL ON DATABASE waypoint_test TO admin",
		}
		for _, stmt := range stmts {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				crdbErr = fmt.Errorf("cockroachdb setup %q: %w", stmt, err)
				conn.Close(ctx)
				return
			}
		}
		conn.Close(ctx)

		crdbConnStr = fmt.Sprintf("postgres://admin:adminpass@%s:%s/waypoint_test?sslmode=disable", host, port.Port())
		crdbBackend = fmt.Sprintf("%s:%s", host, port.Port())

		// Verify admin connection works.
		for i := 0; i < 10; i++ {
			conn, err = pgx.Connect(ctx, crdbConnStr)
			if err == nil {
				conn.Close(ctx)
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if err != nil {
			crdbErr = fmt.Errorf("cockroachdb admin connect after retries: %w", err)
			return
		}
	})

	if crdbErr != nil {
		t.Fatalf("cockroachdb container: %v", crdbErr)
	}

	return crdbConnStr, crdbBackend
}
