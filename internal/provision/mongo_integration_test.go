//go:build integration

package provision

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/testutil"
)

// setupMongoProvisioner returns a provisioner, the admin connection string,
// and the backend address. All three come from a single MongoDBBackend call
// to avoid triggering cleanup between provisioning and verification.
func setupMongoProvisioner(t *testing.T) (*MongoProvisioner, string, string) {
	t.Helper()
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "mongointtest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	connStr, backend := testutil.MongoDBBackend(t)
	p := NewMongoProvisioner("admin", "adminpass", backend, "admin", "wp_", "test", false, store, logger, nil)
	return p, connStr, backend
}

func mongoAdminClient(t *testing.T, connStr string) *mongo.Client {
	t.Helper()
	opts := options.Client().ApplyURI(connStr).SetServerSelectionTimeout(5 * time.Second)
	client, err := mongo.Connect(opts)
	if err != nil {
		t.Fatalf("mongo admin connect: %v", err)
	}
	t.Cleanup(func() { client.Disconnect(context.Background()) })
	return client
}

func mongoUserExists(t *testing.T, client *mongo.Client, username string) bool {
	t.Helper()
	result := client.Database("admin").RunCommand(context.Background(), bson.D{
		{Key: "usersInfo", Value: bson.D{{Key: "user", Value: username}, {Key: "db", Value: "admin"}}},
	})
	var resp struct {
		Users []bson.Raw `bson:"users"`
	}
	if err := result.Decode(&resp); err != nil {
		t.Fatalf("usersInfo: %v", err)
	}
	return len(resp.Users) > 0
}

func dropMongoUser(t *testing.T, client *mongo.Client, username string) {
	t.Helper()
	client.Database("admin").RunCommand(context.Background(), bson.D{
		{Key: "dropUser", Value: username},
	})
}

func TestIntegration_MongoProvisioner_CreateUser(t *testing.T) {
	p, connStr, _ := setupMongoProvisioner(t)
	client := mongoAdminClient(t, connStr)

	roles := []MongoRole{
		{Role: "readWrite", DB: "testdb"},
	}

	user, pass, err := p.EnsureUser(context.Background(), "testuser@example.com", "test-node", roles)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { dropMongoUser(t, client, user) })

	if user == "" || pass == "" {
		t.Fatal("expected non-empty username and password")
	}
	if !mongoUserExists(t, client, user) {
		t.Fatalf("user %q not found after EnsureUser", user)
	}

	// Verify the provisioned user can connect and write.
	userOpts := options.Client().
		ApplyURI(connStr).
		SetAuth(options.Credential{
			AuthMechanism: "SCRAM-SHA-256",
			AuthSource:    "admin",
			Username:      user,
			Password:      pass,
		}).
		SetServerSelectionTimeout(5 * time.Second)
	userClient, err := mongo.Connect(userOpts)
	if err != nil {
		t.Fatalf("connect as provisioned user: %v", err)
	}
	defer userClient.Disconnect(context.Background())

	_, err = userClient.Database("testdb").Collection("test_coll").InsertOne(context.Background(), bson.D{{Key: "x", Value: 1}})
	if err != nil {
		t.Fatalf("insert as provisioned user: %v", err)
	}
}

func TestIntegration_MongoProvisioner_PasswordCaching(t *testing.T) {
	p, connStr, _ := setupMongoProvisioner(t)
	client := mongoAdminClient(t, connStr)

	roles := []MongoRole{{Role: "read", DB: "cachedb"}}

	user, pass1, err := p.EnsureUser(context.Background(), "cacheuser@example.com", "test-node", roles)
	if err != nil {
		t.Fatalf("EnsureUser first: %v", err)
	}
	t.Cleanup(func() { dropMongoUser(t, client, user) })

	// Within the credential TTL window, same password should be reused.
	_, pass2, err := p.EnsureUser(context.Background(), "cacheuser@example.com", "test-node", roles)
	if err != nil {
		t.Fatalf("EnsureUser second: %v", err)
	}

	if pass1 != pass2 {
		t.Fatal("password should be cached and reused within TTL window")
	}

	// The cached password should work for authentication.
	userOpts := options.Client().
		ApplyURI(connStr).
		SetAuth(options.Credential{
			AuthMechanism: "SCRAM-SHA-256",
			AuthSource:    "admin",
			Username:      user,
			Password:      pass1,
		}).
		SetServerSelectionTimeout(5 * time.Second)
	userClient, err := mongo.Connect(userOpts)
	if err != nil {
		t.Fatalf("connect with cached password: %v", err)
	}
	defer userClient.Disconnect(context.Background())
	if err := userClient.Ping(context.Background(), nil); err != nil {
		t.Fatalf("ping with cached password: %v", err)
	}
}

func TestIntegration_MongoProvisioner_PasswordRotationAfterCacheExpiry(t *testing.T) {
	// Use a provisioner with a very short credential TTL to test rotation.
	rdb := testutil.RedisClient(t)
	store := restrict.NewRedisStore(rdb, "mongointtest:", metrics.Noop())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	connStr, backend := testutil.MongoDBBackend(t)
	p := NewMongoProvisioner("admin", "adminpass", backend, "admin", "wp_", "test", false, store, logger, nil)

	client := mongoAdminClient(t, connStr)
	roles := []MongoRole{{Role: "read", DB: "rotatedb"}}

	user, pass1, err := p.EnsureUser(context.Background(), "rotateuser@example.com", "test-node", roles)
	if err != nil {
		t.Fatalf("EnsureUser first: %v", err)
	}
	t.Cleanup(func() { dropMongoUser(t, client, user) })

	// Expire the cache entry manually.
	p.credCache.Delete(user)

	_, pass2, err := p.EnsureUser(context.Background(), "rotateuser@example.com", "test-node", roles)
	if err != nil {
		t.Fatalf("EnsureUser second: %v", err)
	}

	if pass1 == pass2 {
		t.Fatal("password should rotate after cache expiry")
	}

	// New password should work.
	newOpts := options.Client().
		ApplyURI(connStr).
		SetAuth(options.Credential{
			AuthMechanism: "SCRAM-SHA-256",
			AuthSource:    "admin",
			Username:      user,
			Password:      pass2,
		}).
		SetServerSelectionTimeout(5 * time.Second)
	newClient, err := mongo.Connect(newOpts)
	if err != nil {
		t.Fatalf("connect with new password: %v", err)
	}
	defer newClient.Disconnect(context.Background())
	if err := newClient.Ping(context.Background(), nil); err != nil {
		t.Fatalf("ping with new password: %v", err)
	}
}

func TestIntegration_MongoProvisioner_ConcurrentConnections(t *testing.T) {
	p, connStr, _ := setupMongoProvisioner(t)
	client := mongoAdminClient(t, connStr)

	roles := []MongoRole{{Role: "readWrite", DB: "concdb"}}

	// Compute the expected username and expire any cached entry to force
	// fresh provisioning. Use the provisioner's own formatting to avoid
	// hardcoding the sanitization logic.
	expectedUser := p.formatUsername("concurrent@example.com", "test-node")
	p.credCache.Delete(expectedUser)

	// Run multiple EnsureUser calls concurrently for the same user.
	const concurrency = 5
	type result struct {
		user string
		pass string
		err  error
	}
	results := make(chan result, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			u, pw, err := p.EnsureUser(context.Background(), "concurrent@example.com", "test-node", roles)
			results <- result{u, pw, err}
		}()
	}

	var passwords []string
	var username string
	for i := 0; i < concurrency; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("EnsureUser: %v", r.err)
		}
		username = r.user
		passwords = append(passwords, r.pass)
	}
	t.Cleanup(func() { dropMongoUser(t, client, username) })

	// All concurrent calls should return the same password (cached).
	for i := 1; i < len(passwords); i++ {
		if passwords[i] != passwords[0] {
			t.Fatalf("concurrent calls returned different passwords: %q vs %q", passwords[0], passwords[i])
		}
	}

	// The password should actually work.
	userOpts := options.Client().
		ApplyURI(connStr).
		SetAuth(options.Credential{
			AuthMechanism: "SCRAM-SHA-256",
			AuthSource:    "admin",
			Username:      username,
			Password:      passwords[0],
		}).
		SetServerSelectionTimeout(5 * time.Second)
	userClient, err := mongo.Connect(userOpts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer userClient.Disconnect(context.Background())
	if err := userClient.Ping(context.Background(), nil); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestIntegration_MongoProvisioner_RoleReconciliation(t *testing.T) {
	p, connStr, _ := setupMongoProvisioner(t)
	client := mongoAdminClient(t, connStr)

	roles1 := []MongoRole{{Role: "read", DB: "db1"}}
	user, _, err := p.EnsureUser(context.Background(), "roleuser@example.com", "test-node", roles1)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { dropMongoUser(t, client, user) })

	roles2 := []MongoRole{
		{Role: "readWrite", DB: "db1"},
		{Role: "read", DB: "db2"},
	}
	_, _, err = p.EnsureUser(context.Background(), "roleuser@example.com", "test-node", roles2)
	if err != nil {
		t.Fatalf("EnsureUser update: %v", err)
	}

	result := client.Database("admin").RunCommand(context.Background(), bson.D{
		{Key: "usersInfo", Value: bson.D{{Key: "user", Value: user}, {Key: "db", Value: "admin"}}},
	})
	var resp struct {
		Users []struct {
			Roles []struct {
				Role string `bson:"role"`
				DB   string `bson:"db"`
			} `bson:"roles"`
		} `bson:"users"`
	}
	if err := result.Decode(&resp); err != nil {
		t.Fatalf("decode usersInfo: %v", err)
	}
	if len(resp.Users) == 0 {
		t.Fatal("user not found")
	}

	roleMap := make(map[string]string)
	for _, r := range resp.Users[0].Roles {
		roleMap[r.DB] = r.Role
	}
	if roleMap["db1"] != "readWrite" {
		t.Errorf("expected readWrite on db1, got %q", roleMap["db1"])
	}
	if roleMap["db2"] != "read" {
		t.Errorf("expected read on db2, got %q", roleMap["db2"])
	}
}

func TestIntegration_MongoProvisioner_ReadonlyCannotWrite(t *testing.T) {
	p, connStr, _ := setupMongoProvisioner(t)
	client := mongoAdminClient(t, connStr)

	roles := []MongoRole{{Role: "read", DB: "readonlydb"}}

	user, pass, err := p.EnsureUser(context.Background(), "readonly@example.com", "test-node", roles)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { dropMongoUser(t, client, user) })

	// Seed data as admin so the db exists.
	_, err = client.Database("readonlydb").Collection("data").InsertOne(context.Background(), bson.D{{Key: "seed", Value: true}})
	if err != nil {
		t.Fatalf("seed data: %v", err)
	}

	// Connect as readonly user.
	userOpts := options.Client().
		ApplyURI(connStr).
		SetAuth(options.Credential{
			AuthMechanism: "SCRAM-SHA-256",
			AuthSource:    "admin",
			Username:      user,
			Password:      pass,
		}).
		SetServerSelectionTimeout(5 * time.Second)
	userClient, err := mongo.Connect(userOpts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer userClient.Disconnect(context.Background())

	// Read should work.
	cur, err := userClient.Database("readonlydb").Collection("data").Find(context.Background(), bson.D{})
	if err != nil {
		t.Fatalf("read should succeed: %v", err)
	}
	cur.Close(context.Background())

	// Write should fail.
	_, err = userClient.Database("readonlydb").Collection("data").InsertOne(context.Background(), bson.D{{Key: "x", Value: 1}})
	if err == nil {
		t.Fatal("insert should be denied for readonly user")
	}
}

func TestIntegration_MongoProvisioner_UsernameFormat(t *testing.T) {
	p, connStr, _ := setupMongoProvisioner(t)
	client := mongoAdminClient(t, connStr)

	roles := []MongoRole{{Role: "read", DB: "fmtdb"}}
	user, _, err := p.EnsureUser(context.Background(), "User.With-Special@corp.example.com", "My-Node.tail1234", roles)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	t.Cleanup(func() { dropMongoUser(t, client, user) })

	if user == "" {
		t.Fatal("expected non-empty username")
	}
	if user[:3] != "wp_" {
		t.Errorf("expected wp_ prefix, got %q", user)
	}
}
