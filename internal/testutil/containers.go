package testutil

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcmongo "github.com/testcontainers/testcontainers-go/modules/mongodb"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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

	mongoOnce    sync.Once
	mongoConnStr string
	mongoBackend string
	mongoErr     error

	// A second, fully independent MongoDB backend used by tests that need to
	// prove two configured clusters route to distinct backends.
	mongoSecondaryOnce    sync.Once
	mongoSecondaryConnStr string
	mongoSecondaryBackend string
	mongoSecondaryErr     error

	mongoRSOnce sync.Once
	mongoRSData *MongoRSInfo
	mongoRSErr  error

	mongoShardedOnce sync.Once
	mongoShardedData *MongoShardedInfo
	mongoShardedErr  error

	openSearchOnce    sync.Once
	openSearchBackend string
	openSearchErr     error
)

// OpenSearchAdminUser and OpenSearchAdminPassword are the admin credentials the
// shared OpenSearch test container is bootstrapped with.
const (
	OpenSearchAdminUser     = "admin"
	OpenSearchAdminPassword = "Wp_Str0ng_Passw0rd!"
)

// MongoRSInfo contains connection info for a multi-node MongoDB replica set.
type MongoRSInfo struct {
	ConnStr string   // mongodb://admin:adminpass@host1:port1,host2:port2,host3:port3/?replicaSet=rs0&authSource=admin
	Primary string   // host:port of the primary (mapped port on host)
	Members []string // all member host:port addresses (mapped ports on host)
}

// MongoShardedInfo contains connection info for a sharded MongoDB cluster
// (config-server replica set + shard replica sets fronted by mongos routers).
type MongoShardedInfo struct {
	ConnStr string   // mongodb://admin:adminpass@mongos1,mongos2/?authSource=admin
	Mongos  []string // mapped host:port for each mongos router
}

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

// MongoDBBackend starts a shared MongoDB 8 container with authentication
// enabled (once per test binary) and returns the admin connection string
// and host:port backend address.
func MongoDBBackend(t *testing.T) (connStr string, backend string) {
	t.Helper()

	mongoOnce.Do(func() {
		mongoConnStr, mongoBackend, mongoErr = startMongoBackendContainer()
	})

	if mongoErr != nil {
		t.Fatalf("mongodb container: %v", mongoErr)
	}

	cleanupMongoBackend(mongoConnStr)
	return mongoConnStr, mongoBackend
}

// MongoDBBackendSecondary starts a second, fully independent MongoDB container
// (once per test binary) and returns its connection info. It exists so tests can
// configure two distinct clusters and verify each listener routes to its own
// backend rather than both pointing at the same one.
func MongoDBBackendSecondary(t *testing.T) (connStr string, backend string) {
	t.Helper()

	mongoSecondaryOnce.Do(func() {
		mongoSecondaryConnStr, mongoSecondaryBackend, mongoSecondaryErr = startMongoBackendContainer()
	})

	if mongoSecondaryErr != nil {
		t.Fatalf("secondary mongodb container: %v", mongoSecondaryErr)
	}

	cleanupMongoBackend(mongoSecondaryConnStr)
	return mongoSecondaryConnStr, mongoSecondaryBackend
}

// startMongoBackendContainer runs a standalone mongo:8 container with
// admin/adminpass and waits until it accepts connections.
func startMongoBackendContainer() (connStr string, backend string, err error) {
	ctx := context.Background()
	container, err := tcmongo.Run(ctx, "mongo:8",
		tcmongo.WithUsername("admin"),
		tcmongo.WithPassword("adminpass"),
	)
	if err != nil {
		return "", "", fmt.Errorf("start mongodb container: %w", err)
	}

	cs, err := container.ConnectionString(ctx)
	if err != nil {
		return "", "", fmt.Errorf("mongodb connection string: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		return "", "", fmt.Errorf("mongodb host: %w", err)
	}

	port, err := container.MappedPort(ctx, "27017/tcp")
	if err != nil {
		return "", "", fmt.Errorf("mongodb port: %w", err)
	}

	opts := options.Client().ApplyURI(cs).SetServerSelectionTimeout(30 * time.Second)
	var client *mongo.Client
	for i := 0; i < 20; i++ {
		client, err = mongo.Connect(opts)
		if err == nil {
			err = client.Ping(ctx, nil)
			if err == nil {
				client.Disconnect(ctx)
				break
			}
			client.Disconnect(ctx)
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		return "", "", fmt.Errorf("mongodb connect after reconfig: %w", err)
	}

	return cs, fmt.Sprintf("%s:%s", host, port.Port()), nil
}

// cleanupMongoBackend drops non-system databases and provisioned (wp_) users so
// each test starts from a clean slate on a shared backend.
func cleanupMongoBackend(connStr string) {
	ctx := context.Background()
	opts := options.Client().ApplyURI(connStr)
	client, err := mongo.Connect(opts)
	if err != nil {
		return
	}
	names, _ := client.ListDatabaseNames(ctx, bson.M{})
	for _, name := range names {
		if name != "admin" && name != "local" && name != "config" {
			client.Database(name).Drop(ctx)
		}
	}
	// Drop provisioned users (wp_ prefix) but keep the admin user.
	result := client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "usersInfo", Value: 1},
	})
	var resp struct {
		Users []struct {
			User string `bson:"user"`
		} `bson:"users"`
	}
	if result.Err() == nil {
		if err := result.Decode(&resp); err == nil {
			for _, u := range resp.Users {
				if strings.HasPrefix(u.User, "wp_") {
					client.Database("admin").RunCommand(ctx, bson.D{
						{Key: "dropUser", Value: u.User},
					})
				}
			}
		}
	}
	client.Disconnect(ctx)
}

// MongoDBReplicaSet starts a shared 3-node MongoDB replica set (once per test
// binary) and returns connection info. The RS uses auth with admin/adminpass.
// Each call cleans up provisioned users and non-system databases for isolation.
func MongoDBReplicaSet(t *testing.T) *MongoRSInfo {
	t.Helper()

	mongoRSOnce.Do(func() {
		ctx := context.Background()

		// Create a Docker network for inter-member communication.
		nw, err := network.New(ctx)
		if err != nil {
			mongoRSErr = fmt.Errorf("create docker network: %w", err)
			return
		}

		// Generate a shared keyFile for RS internal auth.
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			mongoRSErr = fmt.Errorf("generate keyfile: %w", err)
			return
		}
		keyContent := base64.StdEncoding.EncodeToString(keyBytes)

		// Entrypoint script: write keyfile, fix permissions, start mongod.
		mkScript := func(name string) string {
			return fmt.Sprintf(`#!/bin/sh
set -e
echo '%s' > /tmp/keyfile
chmod 400 /tmp/keyfile
chown 999:999 /tmp/keyfile
exec mongod --replSet rs0 --keyFile /tmp/keyfile --bind_ip_all --port 27017
`, keyContent)
		}

		memberNames := []string{"mongo1", "mongo2", "mongo3"}
		type containerResult struct {
			container testcontainers.Container
			err       error
		}
		results := make([]chan containerResult, 3)

		// Start all 3 members in parallel.
		for i, name := range memberNames {
			results[i] = make(chan containerResult, 1)
			go func(idx int, alias string) {
				c, cerr := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
					ContainerRequest: testcontainers.ContainerRequest{
						Image:        "mongo:8",
						ExposedPorts: []string{"27017/tcp"},
						Entrypoint:   []string{"/bin/sh", "-c", mkScript(alias)},
						Networks:     []string{nw.Name},
						NetworkAliases: map[string][]string{
							nw.Name: {alias},
						},
						WaitingFor: wait.ForLog("Waiting for connections").
							WithStartupTimeout(90 * time.Second),
					},
					Started: true,
				})
				results[idx] <- containerResult{container: c, err: cerr}
			}(i, name)
		}

		containers := make([]testcontainers.Container, 3)
		for i := range containers {
			r := <-results[i]
			if r.err != nil {
				mongoRSErr = fmt.Errorf("start %s: %w", memberNames[i], r.err)
				return
			}
			containers[i] = r.container
		}

		// Run rs.initiate() on the first member via direct localhost connection.
		// Using mongosh --host localhost avoids RS topology discovery which
		// would hang during election.
		rsInitCmd := `rs.initiate({
			_id: "rs0",
			members: [
				{ _id: 0, host: "mongo1:27017", priority: 2 },
				{ _id: 1, host: "mongo2:27017", priority: 1 },
				{ _id: 2, host: "mongo3:27017", priority: 1 }
			]
		})`
		code, _, execErr := containers[0].Exec(ctx, []string{
			"mongosh", "--host", "localhost", "--port", "27017", "--eval", rsInitCmd,
		})
		if execErr != nil {
			mongoRSErr = fmt.Errorf("rs.initiate exec: %w", execErr)
			return
		}
		if code != 0 {
			mongoRSErr = fmt.Errorf("rs.initiate exit code: %d", code)
			return
		}

		// Wait for primary election by polling rs.status() on the first member.
		// Use --host localhost to avoid RS topology discovery in mongosh.
		var primaryFound bool
		for i := 0; i < 60; i++ {
			code, _, _ := containers[0].Exec(ctx, []string{
				"mongosh", "--host", "localhost", "--port", "27017", "--quiet", "--eval",
				`const s = rs.status(); const hasPrimary = s.members && s.members.some(m => m.stateStr === "PRIMARY"); if (hasPrimary) { print("OK"); quit(0); } else { quit(1); }`,
			})
			if code == 0 {
				primaryFound = true
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !primaryFound {
			mongoRSErr = fmt.Errorf("RS primary election timed out after 120s")
			return
		}

		// Create admin user via localhost exception on the primary.
		// Try each member since we don't know which became primary.
		createUserCmd := `db.getSiblingDB("admin").createUser({
			user: "admin",
			pwd: "adminpass",
			roles: [{ role: "root", db: "admin" }]
		})`
		var userCreated bool
		for attempt := 0; attempt < 30; attempt++ {
			for _, c := range containers {
				code, _, execErr = c.Exec(ctx, []string{
					"mongosh", "--host", "localhost", "--port", "27017", "--eval", createUserCmd,
				})
				if execErr == nil && code == 0 {
					userCreated = true
					break
				}
			}
			if userCreated {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !userCreated {
			mongoRSErr = fmt.Errorf("create admin user failed on all members")
			return
		}

		// Collect mapped ports for all members.
		var memberAddrs []string
		hostIP, err := containers[0].Host(ctx)
		if err != nil {
			mongoRSErr = fmt.Errorf("get host: %w", err)
			return
		}

		for i, c := range containers {
			port, err := c.MappedPort(ctx, "27017/tcp")
			if err != nil {
				mongoRSErr = fmt.Errorf("mapped port %s: %w", memberNames[i], err)
				return
			}
			memberAddrs = append(memberAddrs, fmt.Sprintf("%s:%s", hostIP, port.Port()))
		}

		// Verify connectivity via direct connection to each member.
		var primaryIdx int
		for i, addr := range memberAddrs {
			directURI := fmt.Sprintf("mongodb://admin:adminpass@%s/?authSource=admin&directConnection=true", addr)
			directOpts := options.Client().ApplyURI(directURI).SetServerSelectionTimeout(30 * time.Second)
			var client *mongo.Client
			for attempt := 0; attempt < 15; attempt++ {
				client, err = mongo.Connect(directOpts)
				if err == nil {
					err = client.Ping(ctx, nil)
					if err == nil {
						break
					}
					client.Disconnect(ctx)
				}
				time.Sleep(2 * time.Second)
			}
			if err != nil {
				mongoRSErr = fmt.Errorf("RS member %s connect/ping: %w", memberNames[i], err)
				return
			}

			// Check if this is the primary.
			result := client.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}})
			var helloResp struct {
				IsWritablePrimary bool `bson:"isWritablePrimary"`
			}
			if result.Err() == nil {
				if decErr := result.Decode(&helloResp); decErr == nil && helloResp.IsWritablePrimary {
					primaryIdx = i
				}
			}
			client.Disconnect(ctx)
		}

		primary := memberAddrs[primaryIdx]
		primaryConnStr := fmt.Sprintf("mongodb://admin:adminpass@%s/?authSource=admin&directConnection=true",
			primary)

		mongoRSData = &MongoRSInfo{
			ConnStr: primaryConnStr,
			Primary: primary,
			Members: memberAddrs,
		}
	})

	if mongoRSErr != nil {
		t.Fatalf("mongodb replica set: %v", mongoRSErr)
	}

	// Clean up provisioned users and non-system databases.
	// Use direct connection to the primary to avoid RS topology issues.
	ctx := context.Background()
	cleanupURI := fmt.Sprintf("mongodb://admin:adminpass@%s/?authSource=admin&directConnection=true",
		mongoRSData.Primary)
	opts := options.Client().ApplyURI(cleanupURI).SetServerSelectionTimeout(15 * time.Second)
	client, err := mongo.Connect(opts)
	if err == nil {
		names, _ := client.ListDatabaseNames(ctx, bson.M{})
		for _, name := range names {
			if name != "admin" && name != "local" && name != "config" {
				client.Database(name).Drop(ctx)
			}
		}
		result := client.Database("admin").RunCommand(ctx, bson.D{
			{Key: "usersInfo", Value: 1},
		})
		var resp struct {
			Users []struct {
				User string `bson:"user"`
			} `bson:"users"`
		}
		if result.Err() == nil {
			if err := result.Decode(&resp); err == nil {
				for _, u := range resp.Users {
					if strings.HasPrefix(u.User, "wp_") {
						client.Database("admin").RunCommand(ctx, bson.D{
							{Key: "dropUser", Value: u.User},
						})
					}
				}
			}
		}
		client.Disconnect(ctx)
	}

	return mongoRSData
}

// startMongoRSGroup starts an N-node MongoDB replica set on the given docker
// network, initiates it, and waits for a primary. roleFlag is "--configsvr"
// for a config-server RS or "--shardsvr" for a shard RS. Returns the started
// containers (never terminated; they live for the test binary's lifetime).
func startMongoRSGroup(ctx context.Context, nwName, keyContent, replSet, roleFlag string, aliases []string) ([]testcontainers.Container, error) {
	mkScript := func() string {
		return fmt.Sprintf(`#!/bin/sh
set -e
echo '%s' > /tmp/keyfile
chmod 400 /tmp/keyfile
chown 999:999 /tmp/keyfile
exec mongod %s --replSet %s --keyFile /tmp/keyfile --bind_ip_all --port 27017
`, keyContent, roleFlag, replSet)
	}

	type containerResult struct {
		container testcontainers.Container
		err       error
	}
	results := make([]chan containerResult, len(aliases))
	for i, alias := range aliases {
		results[i] = make(chan containerResult, 1)
		go func(idx int, alias string) {
			c, cerr := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
				ContainerRequest: testcontainers.ContainerRequest{
					Image:        "mongo:8",
					ExposedPorts: []string{"27017/tcp"},
					Entrypoint:   []string{"/bin/sh", "-c", mkScript()},
					Networks:     []string{nwName},
					NetworkAliases: map[string][]string{
						nwName: {alias},
					},
					// Ephemeral data dirs via tmpfs so no named volumes are
					// created — avoids exhausting Podman's volume-lock pool
					// when the reaper is disabled (rootless Podman).
					Tmpfs: map[string]string{"/data/db": "rw", "/data/configdb": "rw"},
					WaitingFor: wait.ForLog("Waiting for connections").
						WithStartupTimeout(90 * time.Second),
				},
				Started: true,
			})
			results[idx] <- containerResult{container: c, err: cerr}
		}(i, alias)
	}

	containers := make([]testcontainers.Container, len(aliases))
	for i := range containers {
		r := <-results[i]
		if r.err != nil {
			return nil, fmt.Errorf("start %s: %w", aliases[i], r.err)
		}
		containers[i] = r.container
	}

	// rs.initiate() on the first member via direct localhost connection.
	memberDocs := make([]string, len(aliases))
	for i, alias := range aliases {
		memberDocs[i] = fmt.Sprintf(`{ _id: %d, host: "%s:27017" }`, i, alias)
	}
	rsInitCmd := fmt.Sprintf(`rs.initiate({ _id: "%s", configsvr: %t, members: [%s] })`,
		replSet, roleFlag == "--configsvr", strings.Join(memberDocs, ", "))
	code, _, execErr := containers[0].Exec(ctx, []string{
		"mongosh", "--host", "localhost", "--port", "27017", "--eval", rsInitCmd,
	})
	if execErr != nil {
		return nil, fmt.Errorf("%s rs.initiate exec: %w", replSet, execErr)
	}
	if code != 0 {
		return nil, fmt.Errorf("%s rs.initiate exit code: %d", replSet, code)
	}

	// Wait for primary election.
	for i := 0; i < 60; i++ {
		code, _, _ := containers[0].Exec(ctx, []string{
			"mongosh", "--host", "localhost", "--port", "27017", "--quiet", "--eval",
			`const s = rs.status(); const hasPrimary = s.members && s.members.some(m => m.stateStr === "PRIMARY"); if (hasPrimary) { print("OK"); quit(0); } else { quit(1); }`,
		})
		if code == 0 {
			return containers, nil
		}
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("%s primary election timed out after 120s", replSet)
}

// MongoDBShardedCluster starts a shared sharded MongoDB cluster (once per test
// binary): a 3-node config-server replica set, two 3-node shard replica sets,
// and two mongos routers. Auth uses admin/adminpass with a shared keyFile for
// internal cluster auth. Each call cleans up provisioned users and non-system
// databases (via a mongos) for isolation.
func MongoDBShardedCluster(t *testing.T) *MongoShardedInfo {
	t.Helper()

	mongoShardedOnce.Do(func() {
		ctx := context.Background()

		nw, err := network.New(ctx)
		if err != nil {
			mongoShardedErr = fmt.Errorf("create docker network: %w", err)
			return
		}

		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			mongoShardedErr = fmt.Errorf("generate keyfile: %w", err)
			return
		}
		keyContent := base64.StdEncoding.EncodeToString(keyBytes)

		// Config-server replica set.
		cfgAliases := []string{"cfgsvr1", "cfgsvr2", "cfgsvr3"}
		cfgContainers, err := startMongoRSGroup(ctx, nw.Name, keyContent, "cfg0", "--configsvr", cfgAliases)
		if err != nil {
			mongoShardedErr = fmt.Errorf("config replica set: %w", err)
			return
		}

		// Two shard replica sets.
		shard0Aliases := []string{"shard0a", "shard0b", "shard0c"}
		if _, err := startMongoRSGroup(ctx, nw.Name, keyContent, "shard0", "--shardsvr", shard0Aliases); err != nil {
			mongoShardedErr = fmt.Errorf("shard0 replica set: %w", err)
			return
		}
		shard1Aliases := []string{"shard1a", "shard1b", "shard1c"}
		if _, err := startMongoRSGroup(ctx, nw.Name, keyContent, "shard1", "--shardsvr", shard1Aliases); err != nil {
			mongoShardedErr = fmt.Errorf("shard1 replica set: %w", err)
			return
		}

		// Create the cluster admin user on the config RS via the localhost
		// exception. It is stored on the config servers and is authoritative
		// cluster-wide (visible through mongos).
		createUserCmd := `db.getSiblingDB("admin").createUser({
			user: "admin",
			pwd: "adminpass",
			roles: [{ role: "root", db: "admin" }]
		})`
		var userCreated bool
		for attempt := 0; attempt < 30 && !userCreated; attempt++ {
			for _, c := range cfgContainers {
				code, _, cerr := c.Exec(ctx, []string{
					"mongosh", "--host", "localhost", "--port", "27017", "--eval", createUserCmd,
				})
				if cerr == nil && code == 0 {
					userCreated = true
					break
				}
			}
			if !userCreated {
				time.Sleep(2 * time.Second)
			}
		}
		if !userCreated {
			mongoShardedErr = fmt.Errorf("create admin user on config RS failed")
			return
		}

		// Start mongos routers pointing at the config RS.
		configDB := "cfg0/cfgsvr1:27017,cfgsvr2:27017,cfgsvr3:27017"
		// userCacheInvalidationIntervalSecs is lowered to its minimum (1s) so a
		// user provisioned through one mongos becomes authable on the other
		// mongos quickly. With the 30s default, a freshly created user is not
		// immediately visible cluster-wide, which surfaces as transient backend
		// auth failures when a client hits a different mongos than the one that
		// provisioned it.
		mongosScript := fmt.Sprintf(`#!/bin/sh
set -e
echo '%s' > /tmp/keyfile
chmod 400 /tmp/keyfile
chown 999:999 /tmp/keyfile
exec mongos --configdb %s --keyFile /tmp/keyfile --bind_ip_all --port 27017 --setParameter userCacheInvalidationIntervalSecs=1
`, keyContent, configDB)

		mongosAliases := []string{"mongos1", "mongos2"}
		type containerResult struct {
			container testcontainers.Container
			err       error
		}
		mongosResults := make([]chan containerResult, len(mongosAliases))
		for i, alias := range mongosAliases {
			mongosResults[i] = make(chan containerResult, 1)
			go func(idx int, alias string) {
				c, cerr := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
					ContainerRequest: testcontainers.ContainerRequest{
						Image:        "mongo:8",
						ExposedPorts: []string{"27017/tcp"},
						Entrypoint:   []string{"/bin/sh", "-c", mongosScript},
						Networks:     []string{nw.Name},
						NetworkAliases: map[string][]string{
							nw.Name: {alias},
						},
						// mongos keeps no data dir; tmpfs avoids the image's
						// declared VOLUME creating a named volume.
						Tmpfs: map[string]string{"/data/db": "rw", "/data/configdb": "rw"},
						WaitingFor: wait.ForLog("Waiting for connections").
							WithStartupTimeout(90 * time.Second),
					},
					Started: true,
				})
				mongosResults[idx] <- containerResult{container: c, err: cerr}
			}(i, alias)
		}
		mongosContainers := make([]testcontainers.Container, len(mongosAliases))
		for i := range mongosContainers {
			r := <-mongosResults[i]
			if r.err != nil {
				mongoShardedErr = fmt.Errorf("start %s: %w", mongosAliases[i], r.err)
				return
			}
			mongosContainers[i] = r.container
		}

		// Add both shards via a mongos (authenticated as admin).
		addShardCmd := `sh.addShard("shard0/shard0a:27017,shard0b:27017,shard0c:27017");
			sh.addShard("shard1/shard1a:27017,shard1b:27017,shard1c:27017");`
		var shardsAdded bool
		for attempt := 0; attempt < 30 && !shardsAdded; attempt++ {
			code, _, cerr := mongosContainers[0].Exec(ctx, []string{
				"mongosh", "--host", "localhost", "--port", "27017",
				"-u", "admin", "-p", "adminpass", "--authenticationDatabase", "admin",
				"--eval", addShardCmd,
			})
			if cerr == nil && code == 0 {
				shardsAdded = true
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !shardsAdded {
			mongoShardedErr = fmt.Errorf("add shards failed")
			return
		}

		// Collect mapped mongos addresses.
		hostIP, err := mongosContainers[0].Host(ctx)
		if err != nil {
			mongoShardedErr = fmt.Errorf("get host: %w", err)
			return
		}
		var mongosAddrs []string
		for i, c := range mongosContainers {
			port, err := c.MappedPort(ctx, "27017/tcp")
			if err != nil {
				mongoShardedErr = fmt.Errorf("mapped port %s: %w", mongosAliases[i], err)
				return
			}
			mongosAddrs = append(mongosAddrs, fmt.Sprintf("%s:%s", hostIP, port.Port()))
		}

		// Verify connectivity through the mongos routers.
		connStr := fmt.Sprintf("mongodb://admin:adminpass@%s/?authSource=admin", strings.Join(mongosAddrs, ","))
		verifyOpts := options.Client().ApplyURI(connStr).SetServerSelectionTimeout(30 * time.Second)
		var client *mongo.Client
		for attempt := 0; attempt < 15; attempt++ {
			client, err = mongo.Connect(verifyOpts)
			if err == nil {
				if err = client.Ping(ctx, nil); err == nil {
					break
				}
				client.Disconnect(ctx)
			}
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			mongoShardedErr = fmt.Errorf("connect to mongos: %w", err)
			return
		}
		client.Disconnect(ctx)

		mongoShardedData = &MongoShardedInfo{
			ConnStr: connStr,
			Mongos:  mongosAddrs,
		}
	})

	if mongoShardedErr != nil {
		t.Fatalf("mongodb sharded cluster: %v", mongoShardedErr)
	}

	// Clean up provisioned users and non-system databases via a mongos.
	ctx := context.Background()
	opts := options.Client().ApplyURI(mongoShardedData.ConnStr).SetServerSelectionTimeout(15 * time.Second)
	client, err := mongo.Connect(opts)
	if err == nil {
		names, _ := client.ListDatabaseNames(ctx, bson.M{})
		for _, name := range names {
			if name != "admin" && name != "local" && name != "config" {
				client.Database(name).Drop(ctx)
			}
		}
		result := client.Database("admin").RunCommand(ctx, bson.D{
			{Key: "usersInfo", Value: 1},
		})
		var resp struct {
			Users []struct {
				User string `bson:"user"`
			} `bson:"users"`
		}
		if result.Err() == nil {
			if err := result.Decode(&resp); err == nil {
				for _, u := range resp.Users {
					if strings.HasPrefix(u.User, "wp_") {
						client.Database("admin").RunCommand(ctx, bson.D{
							{Key: "dropUser", Value: u.User},
						})
					}
				}
			}
		}
		client.Disconnect(ctx)
	}

	return mongoShardedData
}

// OpenSearchBackend starts a shared single-node OpenSearch container (once per
// test binary) with the Security plugin enabled and returns its host:port
// backend address. The Security REST layer runs over plain HTTP (TLS disabled)
// so the provisioner can be exercised without certificate wiring. Admin
// credentials are OpenSearchAdminUser / OpenSearchAdminPassword.
func OpenSearchBackend(t *testing.T) string {
	t.Helper()

	openSearchOnce.Do(func() {
		openSearchBackend, openSearchErr = startOpenSearchContainer()
	})
	if openSearchErr != nil {
		t.Fatalf("opensearch container: %v", openSearchErr)
	}
	return openSearchBackend
}

func startOpenSearchContainer() (string, error) {
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "opensearchproject/opensearch:2.19.0",
			ExposedPorts: []string{"9200/tcp"},
			Env: map[string]string{
				"discovery.type":                    "single-node",
				"plugins.security.ssl.http.enabled": "false",
				"OPENSEARCH_INITIAL_ADMIN_PASSWORD": OpenSearchAdminPassword,
				"bootstrap.memory_lock":             "false",
				"OPENSEARCH_JAVA_OPTS":              "-Xms512m -Xmx512m",
				"DISABLE_INSTALL_DEMO_CONFIG":       "false",
			},
			WaitingFor: wait.ForHTTP("/_cluster/health").
				WithPort("9200/tcp").
				WithBasicAuth(OpenSearchAdminUser, OpenSearchAdminPassword).
				WithStatusCodeMatcher(func(status int) bool { return status == 200 }).
				WithStartupTimeout(180 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		return "", fmt.Errorf("start opensearch container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("opensearch host: %w", err)
	}
	port, err := container.MappedPort(ctx, "9200/tcp")
	if err != nil {
		return "", fmt.Errorf("opensearch port: %w", err)
	}
	return fmt.Sprintf("%s:%s", host, port.Port()), nil
}
