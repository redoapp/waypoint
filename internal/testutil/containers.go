package testutil

import (
	"context"
	"fmt"
	"strings"
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

	redisClusterOnce   sync.Once
	redisClusterClient *redis.Client
	redisClusterErr    error

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

// RedisClusterClient starts a single-node Redis in cluster mode (once per test binary)
// and returns a connected client. The server enforces cluster hash slot semantics,
// so multi-key Lua scripts operating across different slots will fail with CROSSSLOT
// errors — exactly like a production Redis Cluster would.
func RedisClusterClient(t *testing.T) *redis.Client {
	t.Helper()

	redisClusterOnce.Do(func() {
		ctx := context.Background()

		container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "redis:7-alpine",
				ExposedPorts: []string{"6379/tcp"},
				Cmd:          []string{"redis-server", "--cluster-enabled", "yes", "--cluster-config-file", "nodes.conf", "--cluster-node-timeout", "5000"},
				WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
			},
			Started: true,
		})
		if err != nil {
			redisClusterErr = fmt.Errorf("start redis cluster container: %w", err)
			return
		}

		host, err := container.Host(ctx)
		if err != nil {
			redisClusterErr = fmt.Errorf("redis cluster host: %w", err)
			return
		}

		port, err := container.MappedPort(ctx, "6379/tcp")
		if err != nil {
			redisClusterErr = fmt.Errorf("redis cluster port: %w", err)
			return
		}

		addr := fmt.Sprintf("%s:%s", host, port.Port())

		// Assign all 16384 slots to this single node using ADDSLOTSRANGE (Redis 7+).
		code, _, execErr := container.Exec(ctx, []string{
			"redis-cli", "CLUSTER", "ADDSLOTSRANGE", "0", "16383",
		})
		if execErr != nil {
			redisClusterErr = fmt.Errorf("redis cluster addslotsrange: %w", execErr)
			return
		}
		if code != 0 {
			redisClusterErr = fmt.Errorf("redis cluster addslotsrange: exit code %d", code)
			return
		}

		// Wait for cluster to become ready.
		redisClusterClient = redis.NewClient(&redis.Options{Addr: addr})
		for i := 0; i < 30; i++ {
			info, err := redisClusterClient.ClusterInfo(ctx).Result()
			if err == nil && strings.Contains(info, "cluster_state:ok") {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		if err := redisClusterClient.Ping(ctx).Err(); err != nil {
			redisClusterErr = fmt.Errorf("redis cluster ping: %w", err)
			return
		}
	})

	if redisClusterErr != nil {
		t.Fatalf("redis cluster container: %v", redisClusterErr)
	}

	// Flush before each test for isolation.
	if err := redisClusterClient.FlushAll(context.Background()).Err(); err != nil {
		t.Fatalf("redis cluster flushall: %v", err)
	}

	return redisClusterClient
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

		// Generate certs and start in secure mode so passwords work.
		// --accept-sql-without-tls lets clients connect over plain TCP.
		initScript := `#!/bin/sh
set -e
mkdir -p /cockroach/certs /cockroach/ca-key
cockroach cert create-ca --certs-dir=/cockroach/certs --ca-key=/cockroach/ca-key/ca.key
cockroach cert create-node localhost 127.0.0.1 --certs-dir=/cockroach/certs --ca-key=/cockroach/ca-key/ca.key
cockroach cert create-client root --certs-dir=/cockroach/certs --ca-key=/cockroach/ca-key/ca.key
exec cockroach start-single-node --certs-dir=/cockroach/certs --accept-sql-without-tls
`
		container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        "cockroachdb/cockroach:latest-v24.3",
				ExposedPorts: []string{"26257/tcp"},
				Entrypoint:   []string{"/bin/sh", "-c", initScript},
				WaitingFor: wait.ForLog("CockroachDB node starting at").
					WithStartupTimeout(2 * time.Minute),
			},
			Started: true,
		})
		if err != nil {
			crdbErr = fmt.Errorf("start cockroachdb container: %w", err)
			return
		}

		// Set root password via exec so we can connect over plaintext TCP.
		code, _, execErr := container.Exec(ctx, []string{
			"cockroach", "sql", "--certs-dir=/cockroach/certs",
			"-e", "ALTER USER root WITH PASSWORD 'rootpass'",
		})
		if execErr != nil {
			crdbErr = fmt.Errorf("cockroachdb set root password: %w", execErr)
			return
		}
		if code != 0 {
			crdbErr = fmt.Errorf("cockroachdb set root password: exit code %d", code)
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

		cs := fmt.Sprintf("postgres://root:rootpass@%s:%s/defaultdb?sslmode=disable", host, port.Port())

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
		// Use "wpadmin" because "admin" is a built-in CockroachDB role.
		stmts := []string{
			"CREATE DATABASE IF NOT EXISTS waypoint_test",
			"CREATE USER IF NOT EXISTS wpadmin WITH PASSWORD 'adminpass'",
			"GRANT admin TO wpadmin",
			"GRANT ALL ON DATABASE waypoint_test TO wpadmin",
		}
		for _, stmt := range stmts {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				crdbErr = fmt.Errorf("cockroachdb setup %q: %w", stmt, err)
				conn.Close(ctx)
				return
			}
		}
		conn.Close(ctx)

		crdbConnStr = fmt.Sprintf("postgres://wpadmin:adminpass@%s:%s/waypoint_test?sslmode=disable", host, port.Port())
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
