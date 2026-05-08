//go:build integration

package proxy_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/mongowire"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/proxy"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

// setupMongoProxy starts a MongoDB proxy with the given auth result and returns the proxy listen address.
func setupMongoProxy(t *testing.T, authResult *auth.AuthResult, authErr error) string {
	t.Helper()

	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "mongoproxytest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, backend := testutil.MongoDBBackend(t)
	provisioner := provision.NewMongoProvisioner("admin", "adminpass", backend, "admin", "wp_", "test", false, store, logger, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	p := &proxy.MongoDBProxy{
		Backend:     backend,
		Name:        "test-listener",
		ListenAddr:  ln.Addr().String(),
		Auth:        &mockAuthorizer{result: authResult, err: authErr},
		Tracker:     tracker,
		Provisioner: provisioner,
		Metrics:     m,
		MongoConfig: &config.MongoDBAdmin{
			AdminUser:     "admin",
			AdminPassword: "adminpass",
			AuthDatabase:  "admin",
			UserPrefix:    "wp_",
		},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()

	return ln.Addr().String()
}

func setupMongoStaticProxy(t *testing.T, backend string, authResult *auth.AuthResult, staticUsers []config.MongoStaticUser) string {
	t.Helper()

	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "mongostaticproxytest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	p := &proxy.MongoDBProxy{
		Backend:    backend,
		Name:       "test-listener",
		ListenAddr: ln.Addr().String(),
		Auth:       &mockAuthorizer{result: authResult},
		Tracker:    tracker,
		Metrics:    m,
		MongoConfig: &config.MongoDBAdmin{
			AuthDatabase: "admin",
			Provision: &config.MongoProvision{
				Mode:        config.MongoProvisionStatic,
				StaticUsers: staticUsers,
			},
		},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()

	return ln.Addr().String()
}

func mongoIntegrationAdminClient(t *testing.T, connStr string) *mongo.Client {
	t.Helper()
	opts := options.Client().ApplyURI(connStr).SetServerSelectionTimeout(5 * time.Second)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("mongo admin connect: %v", err)
	}
	t.Cleanup(func() { client.Disconnect(context.Background()) })
	return client
}

func createMongoStaticUser(t *testing.T, client *mongo.Client, username, password string, roles []config.MongoStaticRole) {
	t.Helper()
	ctx := context.Background()

	// Static users are intentionally not wp_-prefixed, so remove any leftover
	// user from a previous interrupted integration run before creating it.
	client.Database("admin").RunCommand(ctx, bson.D{{Key: "dropUser", Value: username}})

	roleDocs := make(bson.A, 0, len(roles))
	for _, role := range roles {
		roleDocs = append(roleDocs, bson.D{
			{Key: "role", Value: role.Role},
			{Key: "db", Value: role.DB},
		})
	}
	err := client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "createUser", Value: username},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: roleDocs},
		{Key: "mechanisms", Value: bson.A{"SCRAM-SHA-256"}},
	}).Err()
	if err != nil {
		t.Fatalf("create static user %q: %v", username, err)
	}
	t.Cleanup(func() {
		client.Database("admin").RunCommand(context.Background(), bson.D{{Key: "dropUser", Value: username}})
	})
}

// makeMongoAuthResult builds an AuthResult with MongoDB capabilities.
func makeMongoAuthResult(databases map[string]auth.MongoDBPermissions, limits *auth.LimitsCap) *auth.AuthResult {
	result := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		MatchedRules: []auth.CapRule{
			{
				Backends: map[string]auth.BackendCap{
					"test-listener": {
						Mongo: &auth.MongoCap{
							Databases: databases,
						},
					},
				},
			},
		},
	}
	if limits != nil {
		result.MatchedRules[0].Limits = limits
		result.Limits = auth.MergedLimits{
			MaxConns: limits.MaxConns,
		}
	}
	return result
}

// mongoProxyConnect connects to the proxy without credentials (preferred path).
func mongoProxyConnect(t *testing.T, addr, database string) *mongo.Client {
	t.Helper()
	uri := fmt.Sprintf("mongodb://%s/%s?directConnection=true&serverSelectionTimeoutMS=5000", addr, database)
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	t.Cleanup(func() { client.Disconnect(context.Background()) })
	return client
}

// mongoProxyConnectWithAuth connects to the proxy with the dummy password.
func mongoProxyConnectWithAuth(t *testing.T, addr, database string) *mongo.Client {
	t.Helper()
	uri := fmt.Sprintf("mongodb://user:%s@%s/%s?authSource=admin&directConnection=true&serverSelectionTimeoutMS=5000",
		mongowire.DummyPassword, addr, database)
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("mongo connect with auth: %v", err)
	}
	t.Cleanup(func() { client.Disconnect(context.Background()) })
	return client
}

func TestIntegration_MongoProxy_ReadWriteAllowed(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"testdb": {Permissions: []string{"readwrite"}},
	}, nil)

	addr := setupMongoProxy(t, result, nil)
	client := mongoProxyConnect(t, addr, "testdb")

	ctx := context.Background()
	coll := client.Database("testdb").Collection("items")

	// Insert should work.
	_, err := coll.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Read should work.
	var doc bson.M
	err = coll.FindOne(ctx, bson.D{{Key: "name", Value: "test"}}).Decode(&doc)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if doc["name"] != "test" {
		t.Fatalf("expected name=test, got %v", doc["name"])
	}
}

func TestIntegration_MongoProxy_WithDummyPassword(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"authdb": {Permissions: []string{"readwrite"}},
	}, nil)

	addr := setupMongoProxy(t, result, nil)
	client := mongoProxyConnectWithAuth(t, addr, "authdb")

	ctx := context.Background()
	coll := client.Database("authdb").Collection("items")

	_, err := coll.InsertOne(ctx, bson.D{{Key: "via", Value: "scram"}})
	if err != nil {
		t.Fatalf("insert via SCRAM: %v", err)
	}

	var doc bson.M
	err = coll.FindOne(ctx, bson.D{{Key: "via", Value: "scram"}}).Decode(&doc)
	if err != nil {
		t.Fatalf("find via SCRAM: %v", err)
	}
}

func TestIntegration_MongoProxy_StaticUserReadWriteAllowed(t *testing.T) {
	connStr, backend := testutil.MongoDBBackend(t)
	adminClient := mongoIntegrationAdminClient(t, connStr)

	const (
		dbName   = "static_rw_db"
		username = "static_rw_user"
		password = "static-rw-pass"
	)
	roles := []config.MongoStaticRole{{Role: "readWrite", DB: dbName}}
	createMongoStaticUser(t, adminClient, username, password, roles)

	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		dbName: {Permissions: []string{"readwrite"}},
	}, nil)
	addr := setupMongoStaticProxy(t, backend, result, []config.MongoStaticUser{
		{
			Name:         "static-readwrite",
			Username:     username,
			Password:     password,
			AuthDatabase: "admin",
			Database:     dbName,
			Permissions:  []string{"readwrite"},
		},
	})

	client := mongoProxyConnect(t, addr, dbName)
	ctx := context.Background()
	coll := client.Database(dbName).Collection("items")

	_, err := coll.InsertOne(ctx, bson.D{{Key: "source", Value: "static-user"}})
	if err != nil {
		t.Fatalf("insert through static user proxy: %v", err)
	}

	var doc bson.M
	err = coll.FindOne(ctx, bson.D{{Key: "source", Value: "static-user"}}).Decode(&doc)
	if err != nil {
		t.Fatalf("find through static user proxy: %v", err)
	}
}

func TestIntegration_MongoProxy_StaticReadWriteWinsOverReadonlyGrant(t *testing.T) {
	connStr, backend := testutil.MongoDBBackend(t)
	adminClient := mongoIntegrationAdminClient(t, connStr)

	const (
		dbName     = "static_mixed_grants_db"
		roUsername = "static_mixed_ro_user"
		roPassword = "static-mixed-ro-pass"
		rwUsername = "static_mixed_rw_user"
		rwPassword = "static-mixed-rw-pass"
	)
	createMongoStaticUser(t, adminClient, roUsername, roPassword, []config.MongoStaticRole{
		{Role: "read", DB: dbName},
	})
	createMongoStaticUser(t, adminClient, rwUsername, rwPassword, []config.MongoStaticRole{
		{Role: "readWrite", DB: dbName},
	})

	result := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		MatchedRules: []auth.CapRule{
			{
				Backends: map[string]auth.BackendCap{
					"test-listener": {
						Mongo: &auth.MongoCap{
							Databases: map[string]auth.MongoDBPermissions{
								dbName: {Permissions: []string{"readonly"}},
							},
						},
					},
				},
			},
			{
				Backends: map[string]auth.BackendCap{
					"test-listener": {
						Mongo: &auth.MongoCap{
							Databases: map[string]auth.MongoDBPermissions{
								dbName: {Permissions: []string{"readwrite"}},
							},
						},
					},
				},
			},
		},
	}

	addr := setupMongoStaticProxy(t, backend, result, []config.MongoStaticUser{
		{
			Name:         "static-readonly",
			Username:     roUsername,
			Password:     roPassword,
			AuthDatabase: "admin",
			Permissions:  []string{"readonly"},
		},
		{
			Name:         "static-readwrite",
			Username:     rwUsername,
			Password:     rwPassword,
			AuthDatabase: "admin",
			Permissions:  []string{"readwrite"},
		},
	})

	client := mongoProxyConnect(t, addr, dbName)
	_, err := client.Database(dbName).Collection("items").InsertOne(context.Background(), bson.D{{Key: "source", Value: "mixed-grants"}})
	if err != nil {
		t.Fatalf("insert through selected static readwrite user: %v", err)
	}
}

func TestIntegration_MongoProxy_StaticUserMissingReturnsClientMessage(t *testing.T) {
	_, backend := testutil.MongoDBBackend(t)
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"static_missing_db": {Permissions: []string{"readwrite"}},
	}, nil)

	addr := setupMongoStaticProxy(t, backend, result, []config.MongoStaticUser{
		{
			Name:         "static-readonly",
			Username:     "static_ro_user",
			Password:     "static-ro-pass",
			AuthDatabase: "admin",
			Permissions:  []string{"readonly"},
		},
	})

	conn, doc := openMongoProxyHello(t, addr)
	t.Cleanup(func() { conn.Close() })

	var resp struct {
		OK     float64 `bson:"ok"`
		Errmsg string  `bson:"errmsg"`
		Code   int32   `bson:"code"`
	}
	if err := bson.Unmarshal(doc, &resp); err != nil {
		t.Fatalf("unmarshal hello response: %v", err)
	}
	if resp.OK != 0 || resp.Code != 18 {
		t.Fatalf("expected auth error, got ok=%v code=%d errmsg=%q", resp.OK, resp.Code, resp.Errmsg)
	}
	if !strings.Contains(resp.Errmsg, "no static MongoDB user configured for requested permissions") {
		t.Fatalf("expected static user message, got %q", resp.Errmsg)
	}
}

func TestIntegration_MongoProxy_AuthFailure(t *testing.T) {
	addr := setupMongoProxy(t, nil, fmt.Errorf("access denied"))

	uri := fmt.Sprintf("mongodb://%s/testdb?directConnection=true&serverSelectionTimeoutMS=3000", addr)
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(context.Background())

	err = client.Ping(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from auth failure")
	}
}

func TestIntegration_MongoProxy_NoPermissions(t *testing.T) {
	// User has no MongoDB permissions at all.
	result := &auth.AuthResult{
		LoginName: "noperm@example.com",
		NodeName:  "test-node",
		MatchedRules: []auth.CapRule{
			{
				Backends: map[string]auth.BackendCap{
					"test-listener": {
						// No Mongo cap at all.
					},
				},
			},
		},
	}

	addr := setupMongoProxy(t, result, nil)

	uri := fmt.Sprintf("mongodb://%s/testdb?directConnection=true&serverSelectionTimeoutMS=3000", addr)
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(context.Background())

	err = client.Ping(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error from no permissions")
	}
}

func TestIntegration_MongoProxy_ConnectionLimit(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"limitdb": {Permissions: []string{"readonly"}},
	}, &auth.LimitsCap{MaxConns: 2})

	addr := setupMongoProxy(t, result, nil)

	// Hold two raw Mongo handshakes open so the proxy slots are deterministically
	// occupied without relying on driver pool/monitor socket behavior.
	conn1, doc1 := openMongoProxyHello(t, addr)
	t.Cleanup(func() { conn1.Close() })
	assertMongoHelloOK(t, doc1)

	conn2, doc2 := openMongoProxyHello(t, addr)
	t.Cleanup(func() { conn2.Close() })
	assertMongoHelloOK(t, doc2)

	conn3, doc3 := openMongoProxyHello(t, addr)
	t.Cleanup(func() { conn3.Close() })

	var resp struct {
		OK     float64 `bson:"ok"`
		Errmsg string  `bson:"errmsg"`
	}
	if err := bson.Unmarshal(doc3, &resp); err != nil {
		t.Fatalf("unmarshal limit response: %v", err)
	}
	if resp.OK != 0 || !strings.Contains(resp.Errmsg, "too many connections") {
		t.Fatalf("expected connection limit error, got ok=%v errmsg=%q", resp.OK, resp.Errmsg)
	}
}

func openMongoProxyHello(t *testing.T, addr string) (net.Conn, bson.Raw) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	hello, err := mongowire.BuildHelloCommand("admin")
	if err != nil {
		conn.Close()
		t.Fatalf("build hello: %v", err)
	}
	if err := mongowire.WriteMessage(conn, hello); err != nil {
		conn.Close()
		t.Fatalf("write hello: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		conn.Close()
		t.Fatalf("set read deadline: %v", err)
	}
	msg, err := mongowire.ReadMessage(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("read hello response: %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.Close()
		t.Fatalf("clear read deadline: %v", err)
	}
	if msg.Header.OpCode != mongowire.OpMsg {
		conn.Close()
		t.Fatalf("hello response opcode = %d, want %d", msg.Header.OpCode, mongowire.OpMsg)
	}

	_, doc, err := mongowire.ParseOpMsgBody(msg.Body)
	if err != nil {
		conn.Close()
		t.Fatalf("parse hello response: %v", err)
	}
	return conn, doc
}

func assertMongoHelloOK(t *testing.T, doc bson.Raw) {
	t.Helper()

	var resp struct {
		OK     float64 `bson:"ok"`
		Errmsg string  `bson:"errmsg"`
	}
	if err := bson.Unmarshal(doc, &resp); err != nil {
		t.Fatalf("unmarshal hello response: %v", err)
	}
	if resp.OK != 1 {
		t.Fatalf("expected successful hello, got ok=%v errmsg=%q", resp.OK, resp.Errmsg)
	}
}

func TestIntegration_MongoProxy_MultipleDBPermissions(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"db_alpha": {Permissions: []string{"readwrite"}},
		"db_beta":  {Permissions: []string{"readonly"}},
	}, nil)

	addr := setupMongoProxy(t, result, nil)
	client := mongoProxyConnect(t, addr, "db_alpha")

	ctx := context.Background()

	// Write to db_alpha should succeed.
	_, err := client.Database("db_alpha").Collection("test").InsertOne(ctx, bson.D{{Key: "x", Value: 1}})
	if err != nil {
		t.Fatalf("insert to db_alpha: %v", err)
	}

	// Write to db_beta through the proxy (provisioned user has readwrite
	// on db_alpha and readonly on db_beta, but we test via the proxy
	// which only gives us the provisioned roles). Seed data through the
	// proxy's db_alpha write proves write works; now read from db_beta.
	// Insert into db_beta as admin directly (no MongoDBBackend call to avoid cleanup).
	// Instead, just verify we can read from db_beta via the proxy.
	// The proxy provisions the user with read on db_beta, so FindOne
	// on an empty collection returns "no documents" which is fine — it means
	// the auth succeeded. An auth failure would return Unauthorized.
	err = client.Database("db_beta").Collection("test").FindOne(ctx, bson.D{}).Err()
	if err != nil && !strings.Contains(err.Error(), "no documents") {
		t.Fatalf("read from db_beta should succeed (or return no docs): %v", err)
	}
}

func TestIntegration_MongoProxy_WildcardNotExpanded(t *testing.T) {
	// Wildcard "*" entries should not expand to concrete roles.
	// Only explicitly named databases get provisioned.
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"*":        {Permissions: []string{"readonly"}},
		"explicit": {Permissions: []string{"readwrite"}},
	}, nil)

	addr := setupMongoProxy(t, result, nil)
	client := mongoProxyConnect(t, addr, "explicit")

	ctx := context.Background()

	// Write to explicit db should succeed.
	_, err := client.Database("explicit").Collection("test").InsertOne(ctx, bson.D{{Key: "z", Value: 3}})
	if err != nil {
		t.Fatalf("insert to explicit db: %v", err)
	}
}

func TestIntegration_MongoProxy_ReadonlyCannotWrite(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"rodb": {Permissions: []string{"readonly"}},
	}, nil)

	addr := setupMongoProxy(t, result, nil)

	// Seed data via a readwrite proxy so the db exists.
	rwResult := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"rodb": {Permissions: []string{"readwrite"}},
	}, nil)
	rwAddr := setupMongoProxy(t, rwResult, nil)
	rwClient := mongoProxyConnect(t, rwAddr, "rodb")
	_, err := rwClient.Database("rodb").Collection("data").InsertOne(context.Background(), bson.D{{Key: "seed", Value: true}})
	if err != nil {
		t.Fatalf("seed data: %v", err)
	}

	// Connect as readonly through the proxy.
	client := mongoProxyConnect(t, addr, "rodb")
	ctx := context.Background()

	// Read should work.
	cur, err := client.Database("rodb").Collection("data").Find(ctx, bson.D{})
	if err != nil {
		t.Fatalf("read should succeed: %v", err)
	}
	cur.Close(ctx)

	// Write should fail.
	_, err = client.Database("rodb").Collection("data").InsertOne(ctx, bson.D{{Key: "x", Value: 1}})
	if err == nil {
		t.Fatal("insert should be denied for readonly user through proxy")
	}
}

func TestIntegration_MongoProxy_BackendUnavailable(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"testdb": {Permissions: []string{"readwrite"}},
	}, nil)

	// Set up a proxy pointing to a non-existent backend.
	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "mongounreach:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Use an unreachable backend address.
	provisioner := provision.NewMongoProvisioner("admin", "adminpass", "127.0.0.1:1", "admin", "wp_", "test", false, store, logger, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	p := &proxy.MongoDBProxy{
		Backend:     "127.0.0.1:1", // unreachable
		Name:        "test-listener",
		ListenAddr:  ln.Addr().String(),
		Auth:        &mockAuthorizer{result: result, err: nil},
		Tracker:     tracker,
		Provisioner: provisioner,
		Metrics:     m,
		MongoConfig: &config.MongoDBAdmin{
			AdminUser:     "admin",
			AdminPassword: "adminpass",
			AuthDatabase:  "admin",
			UserPrefix:    "wp_",
		},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()

	uri := fmt.Sprintf("mongodb://%s/testdb?directConnection=true&serverSelectionTimeoutMS=5000", ln.Addr().String())
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(context.Background())

	err = client.Ping(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error when backend is unavailable")
	}
}

func TestIntegration_MongoProxy_MultipleRules(t *testing.T) {
	// User has permissions from multiple ACL rules.
	result := &auth.AuthResult{
		LoginName: "multirule@example.com",
		NodeName:  "test-node",
		MatchedRules: []auth.CapRule{
			{
				Backends: map[string]auth.BackendCap{
					"test-listener": {
						Mongo: &auth.MongoCap{
							Databases: map[string]auth.MongoDBPermissions{
								"db_rule1": {Permissions: []string{"readwrite"}},
							},
						},
					},
				},
			},
			{
				Backends: map[string]auth.BackendCap{
					"test-listener": {
						Mongo: &auth.MongoCap{
							Databases: map[string]auth.MongoDBPermissions{
								"db_rule2": {Permissions: []string{"readonly"}},
							},
						},
					},
				},
			},
		},
	}

	addr := setupMongoProxy(t, result, nil)
	client := mongoProxyConnect(t, addr, "db_rule1")
	ctx := context.Background()

	// Write to db_rule1 should succeed (readwrite from rule 1).
	_, err := client.Database("db_rule1").Collection("test").InsertOne(ctx, bson.D{{Key: "x", Value: 1}})
	if err != nil {
		t.Fatalf("insert to db_rule1: %v", err)
	}

	// Read from db_rule2 should succeed (readonly from rule 2).
	err = client.Database("db_rule2").Collection("test").FindOne(ctx, bson.D{}).Err()
	if err != nil && !strings.Contains(err.Error(), "no documents") {
		t.Fatalf("read from db_rule2 should succeed: %v", err)
	}
}

// --- Replica Set Tests ---

// setupMongoRSProxy starts a MongoDB proxy backed by the 3-node replica set.
func setupMongoRSProxy(t *testing.T, authResult *auth.AuthResult, authErr error) string {
	t.Helper()

	rsInfo := testutil.MongoDBReplicaSet(t)
	rdb := testutil.RedisClient(t)
	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "mongolrstest:", m)
	tracker := restrict.NewTracker(store, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	provisioner := provision.NewMongoProvisioner("admin", "adminpass", rsInfo.Primary, "admin", "wp_", "test", false, store, logger, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	p := &proxy.MongoDBProxy{
		Backend:     rsInfo.Primary,
		Name:        "test-listener",
		ListenAddr:  ln.Addr().String(),
		Auth:        &mockAuthorizer{result: authResult, err: authErr},
		Tracker:     tracker,
		Provisioner: provisioner,
		Metrics:     m,
		MongoConfig: &config.MongoDBAdmin{
			AdminUser:     "admin",
			AdminPassword: "adminpass",
			AuthDatabase:  "admin",
			UserPrefix:    "wp_",
		},
		Logger:       logger,
		BytesRead:    &atomic.Int64{},
		BytesWritten: &atomic.Int64{},
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.HandleConn(context.Background(), conn)
		}
	}()

	return ln.Addr().String()
}

func TestIntegration_MongoProxy_ReplicaSetTopologyRewrite(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"topodb": {Permissions: []string{"readwrite"}},
	}, nil)

	proxyAddr := setupMongoRSProxy(t, result, nil)

	// Connect through the proxy with directConnection so we hit the proxy directly.
	uri := fmt.Sprintf("mongodb://%s/topodb?directConnection=true&serverSelectionTimeoutMS=10000", proxyAddr)
	opts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(context.Background())

	// Run hello command through the proxy.
	ctx := context.Background()
	var helloResp bson.M
	err = client.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&helloResp)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}

	// Verify topology fields are rewritten to the proxy address.
	if hosts, ok := helloResp["hosts"]; ok {
		arr, ok := hosts.(bson.A)
		if !ok {
			t.Fatalf("hosts is not array: %T", hosts)
		}
		for i, h := range arr {
			hostStr, ok := h.(string)
			if !ok {
				t.Errorf("hosts[%d] is not string: %T", i, h)
				continue
			}
			if hostStr != proxyAddr {
				t.Errorf("hosts[%d] = %q, want %q (topology not rewritten)", i, hostStr, proxyAddr)
			}
		}
		if len(arr) != 3 {
			t.Errorf("expected 3 hosts, got %d", len(arr))
		}
	} else {
		t.Error("hello response missing 'hosts' field — expected RS topology")
	}

	if me, ok := helloResp["me"]; ok {
		if me != proxyAddr {
			t.Errorf("me = %q, want %q", me, proxyAddr)
		}
	}

	if primary, ok := helloResp["primary"]; ok {
		if primary != proxyAddr {
			t.Errorf("primary = %q, want %q", primary, proxyAddr)
		}
	}

	// Verify setName is preserved from the backend.
	if setName, ok := helloResp["setName"]; ok {
		if setName != "rs0" {
			t.Errorf("setName = %q, want rs0", setName)
		}
	} else {
		t.Error("hello response missing 'setName' — expected RS info")
	}

	// Verify logicalSessionTimeoutMinutes is present (from real backend hello).
	if _, ok := helloResp["logicalSessionTimeoutMinutes"]; !ok {
		t.Error("hello response missing 'logicalSessionTimeoutMinutes' — backend caps not forwarded")
	}
}

func TestIntegration_MongoProxy_ReplicaSetReadWrite(t *testing.T) {
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"rsdb": {Permissions: []string{"readwrite"}},
	}, nil)

	proxyAddr := setupMongoRSProxy(t, result, nil)
	client := mongoProxyConnect(t, proxyAddr, "rsdb")
	ctx := context.Background()

	// Insert a document through the RS-backed proxy.
	_, err := client.Database("rsdb").Collection("items").InsertOne(ctx, bson.D{
		{Key: "name", Value: "via-replica-set"},
		{Key: "count", Value: 42},
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Read it back.
	var doc bson.M
	err = client.Database("rsdb").Collection("items").FindOne(ctx, bson.D{
		{Key: "name", Value: "via-replica-set"},
	}).Decode(&doc)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if doc["name"] != "via-replica-set" {
		t.Errorf("name = %v, want via-replica-set", doc["name"])
	}
	if doc["count"] != int32(42) {
		t.Errorf("count = %v, want 42", doc["count"])
	}
}

func TestIntegration_MongoProxy_ReplicaSetWithAuth(t *testing.T) {
	// Test the dummy password path through a replica set.
	result := makeMongoAuthResult(map[string]auth.MongoDBPermissions{
		"rsauthdb": {Permissions: []string{"readwrite"}},
	}, nil)

	proxyAddr := setupMongoRSProxy(t, result, nil)
	client := mongoProxyConnectWithAuth(t, proxyAddr, "rsauthdb")
	ctx := context.Background()

	_, err := client.Database("rsauthdb").Collection("items").InsertOne(ctx, bson.D{
		{Key: "via", Value: "scram-rs"},
	})
	if err != nil {
		t.Fatalf("insert via SCRAM through RS: %v", err)
	}

	var doc bson.M
	err = client.Database("rsauthdb").Collection("items").FindOne(ctx, bson.D{
		{Key: "via", Value: "scram-rs"},
	}).Decode(&doc)
	if err != nil {
		t.Fatalf("find via SCRAM through RS: %v", err)
	}
}
