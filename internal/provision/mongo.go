package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/redoapp/waypoint/internal/restrict"
)

// credentialTTL controls how long a cached password is reused before rotation.
// Within this window, concurrent connections for the same user share one password.
const credentialTTL = 30 * time.Second

type cachedCredential struct {
	password string
	expires  time.Time
}

// MongoProvisioner manages dynamic MongoDB user lifecycle.
type MongoProvisioner struct {
	adminURI    string
	authDB      string
	userPrefix  string
	peerService string
	store       *restrict.RedisStore
	logger      *slog.Logger
	dialFunc    func(ctx context.Context, network, addr string) (net.Conn, error)

	// credCache prevents password rotation races between concurrent connections
	// for the same user. Credentials are cached with a short TTL; within that
	// window, EnsureUser updates roles but reuses the existing password.
	credCache sync.Map // map[string]*cachedCredential
}

// NewMongoProvisioner creates a new MongoProvisioner.
func NewMongoProvisioner(adminUser, adminPassword, backend, authDatabase, userPrefix, peerService string, backendTLS bool, store *restrict.RedisStore, logger *slog.Logger, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *MongoProvisioner {
	return NewMongoReplicaSetProvisioner(adminUser, adminPassword, []string{backend}, "", authDatabase, userPrefix, peerService, backendTLS, store, logger, dialFunc)
}

// NewMongoReplicaSetProvisioner creates a Mongo provisioner that can discover
// the primary from a replica set seed list. When replicaSet is empty and a
// single backend is supplied, it uses directConnection=true for standalone
// compatibility.
func NewMongoReplicaSetProvisioner(adminUser, adminPassword string, backends []string, replicaSet, authDatabase, userPrefix, peerService string, backendTLS bool, store *restrict.RedisStore, logger *slog.Logger, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) *MongoProvisioner {
	if userPrefix == "" {
		userPrefix = "wp_"
	}
	if authDatabase == "" {
		authDatabase = "admin"
	}
	uri := mongoAdminURI(adminUser, adminPassword, backends, replicaSet, authDatabase, backendTLS)

	return &MongoProvisioner{
		adminURI:    uri,
		authDB:      authDatabase,
		userPrefix:  userPrefix,
		peerService: peerService,
		store:       store,
		logger:      logger,
		dialFunc:    dialFunc,
	}
}

func mongoAdminURI(adminUser, adminPassword string, backends []string, replicaSet, authDatabase string, backendTLS bool) string {
	cleanBackends := make([]string, 0, len(backends))
	for _, backend := range backends {
		if backend != "" {
			cleanBackends = append(cleanBackends, backend)
		}
	}
	if len(cleanBackends) == 0 {
		cleanBackends = []string{"localhost:27017"}
	}

	q := url.Values{}
	if replicaSet != "" {
		q.Set("replicaSet", replicaSet)
	} else if len(cleanBackends) == 1 {
		// Keep standalone and single-seed behavior from trying to discover
		// internal replica-set addresses unless explicitly configured.
		q.Set("directConnection", "true")
	}
	if backendTLS {
		q.Set("tls", "true")
	}

	query := q.Encode()
	if query != "" {
		query = "?" + query
	}

	return fmt.Sprintf("mongodb://%s@%s/%s%s",
		url.UserPassword(adminUser, adminPassword).String(),
		strings.Join(cleanBackends, ","),
		url.PathEscape(authDatabase),
		query,
	)
}

// EnsureUser creates or updates a dynamic MongoDB user for the given identity
// and node with the specified roles across all permitted databases.
// Returns the MongoDB username and password.
//
// Credentials are cached with a short TTL to prevent password rotation races
// when multiple connections for the same user arrive concurrently.
func (p *MongoProvisioner) EnsureUser(ctx context.Context, loginName, nodeName string, roles []MongoRole) (string, string, error) {
	tracer := otel.Tracer("waypoint")
	ctx, span := tracer.Start(ctx, "waypoint.mongo.provision.ensure_user",
		trace.WithAttributes(
			attribute.String("waypoint.user", loginName),
			attribute.Int("waypoint.role_count", len(roles)),
		),
	)
	defer span.End()

	mongoUser := p.formatUsername(loginName, nodeName)
	p.logger.DebugContext(ctx, "ensuring MongoDB user", "login", loginName, "roles", len(roles))

	// Acquire distributed lock.
	const lockTTL = 30 * time.Second
	const maxRetries = 10
	const retryDelay = 100 * time.Millisecond

	ctx, lockSpan := tracer.Start(ctx, "waypoint.mongo.provision.acquire_lock")
	var lockToken string
	for i := 0; i < maxRetries; i++ {
		token, err := p.store.AcquireLock(ctx, "role:"+mongoUser, lockTTL)
		if err != nil {
			lockSpan.RecordError(err)
			lockSpan.SetStatus(codes.Error, "acquire lock failed")
			lockSpan.End()
			span.RecordError(err)
			return "", "", fmt.Errorf("acquire lock: %w", err)
		}
		if token != "" {
			lockToken = token
			break
		}
		select {
		case <-ctx.Done():
			lockSpan.End()
			return "", "", ctx.Err()
		case <-time.After(retryDelay):
		}
	}
	if lockToken == "" {
		err := fmt.Errorf("could not acquire lock for user %q", mongoUser)
		lockSpan.RecordError(err)
		lockSpan.SetStatus(codes.Error, "lock timeout")
		lockSpan.End()
		span.RecordError(err)
		return "", "", err
	}
	lockSpan.End()
	defer p.store.ReleaseLock(ctx, "role:"+mongoUser, lockToken)
	p.logger.DebugContext(ctx, "acquired lock", "user", mongoUser)

	// Connect to admin database.
	const provisionTimeout = 90 * time.Second
	connCtx, connCancel := context.WithTimeout(ctx, provisionTimeout)
	defer connCancel()

	opts := options.Client().ApplyURI(p.adminURI)
	if p.dialFunc != nil {
		opts.SetDialer(&mongoDialer{dialFunc: p.dialFunc})
	}

	ctx, connectSpan := tracer.Start(ctx, "waypoint.mongo.provision.connect")
	client, err := mongo.Connect(opts)
	if err != nil {
		connectSpan.RecordError(err)
		connectSpan.SetStatus(codes.Error, "connect failed")
		connectSpan.End()
		span.RecordError(err)
		return "", "", fmt.Errorf("admin connect: %w", err)
	}
	connectSpan.End()
	defer client.Disconnect(connCtx)

	if err := client.Ping(connCtx, nil); err != nil {
		span.RecordError(err)
		return "", "", fmt.Errorf("admin ping: %w", err)
	}
	p.logger.DebugContext(ctx, "connected to admin MongoDB")

	adminDB := client.Database(p.authDB)

	// Check credential cache: if we have a recent password for this user,
	// just update roles without changing the password.
	if cached, ok := p.credCache.Load(mongoUser); ok {
		cc := cached.(*cachedCredential)
		if time.Now().Before(cc.expires) {
			// Update roles with cached password (no password rotation).
			_, userSpan := tracer.Start(ctx, "waypoint.mongo.provision.update_roles",
				trace.WithAttributes(attribute.String("waypoint.mongo_user", mongoUser)),
			)

			exists, err := p.userExists(connCtx, adminDB, mongoUser)
			if err != nil {
				userSpan.RecordError(err)
				userSpan.SetStatus(codes.Error, "check user failed")
				userSpan.End()
				span.RecordError(err)
				return "", "", fmt.Errorf("check user: %w", err)
			}

			if exists {
				// User exists and we have cached creds — just update roles.
				if err := p.updateUserRoles(connCtx, adminDB, mongoUser, roles); err != nil {
					userSpan.RecordError(err)
					userSpan.SetStatus(codes.Error, "update roles failed")
					userSpan.End()
					span.RecordError(err)
					return "", "", fmt.Errorf("update roles: %w", err)
				}
				userSpan.End()
				p.store.TouchLastUsed(ctx, mongoUser)
				return mongoUser, cc.password, nil
			}
			// User was deleted externally — fall through to full create.
			userSpan.End()
		}
	}

	// No cached credential or cache expired: generate new password.
	password := generatePassword()

	_, userSpan := tracer.Start(ctx, "waypoint.mongo.provision.ensure",
		trace.WithAttributes(attribute.String("waypoint.mongo_user", mongoUser)),
	)

	exists, err := p.userExists(connCtx, adminDB, mongoUser)
	if err != nil {
		userSpan.RecordError(err)
		userSpan.SetStatus(codes.Error, "check user failed")
		userSpan.End()
		span.RecordError(err)
		return "", "", fmt.Errorf("check user: %w", err)
	}

	if !exists {
		err = p.createUser(connCtx, adminDB, mongoUser, password, roles)
		if err != nil {
			userSpan.RecordError(err)
			userSpan.SetStatus(codes.Error, "create user failed")
			userSpan.End()
			span.RecordError(err)
			return "", "", fmt.Errorf("create user: %w", err)
		}
		p.logger.InfoContext(ctx, "created MongoDB user", "user", mongoUser)
	} else {
		err = p.updateUser(connCtx, adminDB, mongoUser, password, roles)
		if err != nil {
			userSpan.RecordError(err)
			userSpan.SetStatus(codes.Error, "update user failed")
			userSpan.End()
			span.RecordError(err)
			return "", "", fmt.Errorf("update user: %w", err)
		}
	}
	userSpan.End()

	// Cache the credential.
	p.credCache.Store(mongoUser, &cachedCredential{
		password: password,
		expires:  time.Now().Add(credentialTTL),
	})

	p.store.TouchLastUsed(ctx, mongoUser)

	return mongoUser, password, nil
}

func (p *MongoProvisioner) userExists(ctx context.Context, db *mongo.Database, username string) (bool, error) {
	result := db.RunCommand(ctx, bson.D{
		{Key: "usersInfo", Value: bson.D{{Key: "user", Value: username}, {Key: "db", Value: p.authDB}}},
	})
	if result.Err() != nil {
		return false, result.Err()
	}

	var resp struct {
		Users []bson.Raw `bson:"users"`
	}
	if err := result.Decode(&resp); err != nil {
		return false, err
	}
	return len(resp.Users) > 0, nil
}

func (p *MongoProvisioner) createUser(ctx context.Context, db *mongo.Database, username, password string, roles []MongoRole) error {
	cmd := bson.D{
		{Key: "createUser", Value: username},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: roles},
		{Key: "mechanisms", Value: bson.A{"SCRAM-SHA-256"}},
	}
	return db.RunCommand(ctx, cmd).Err()
}

func (p *MongoProvisioner) updateUser(ctx context.Context, db *mongo.Database, username, password string, roles []MongoRole) error {
	cmd := bson.D{
		{Key: "updateUser", Value: username},
		{Key: "pwd", Value: password},
		{Key: "roles", Value: roles},
	}
	return db.RunCommand(ctx, cmd).Err()
}

// updateUserRoles updates the user's roles without changing the password.
func (p *MongoProvisioner) updateUserRoles(ctx context.Context, db *mongo.Database, username string, roles []MongoRole) error {
	cmd := bson.D{
		{Key: "updateUser", Value: username},
		{Key: "roles", Value: roles},
	}
	return db.RunCommand(ctx, cmd).Err()
}

// formatUsername builds: {prefix}{login_sanitized}_{node}
// No database suffix since MongoDB users can have roles across multiple databases.
// Truncated to 128 chars with hash suffix if needed for uniqueness.
func (p *MongoProvisioner) formatUsername(loginName, nodeName string) string {
	sanitized := sanitize(loginName)
	node := sanitize(nodeName)

	name := fmt.Sprintf("%s%s_%s", p.userPrefix, sanitized, node)

	if len(name) <= 128 {
		return name
	}

	// Truncate with hash suffix for uniqueness (mirrors Postgres provisioner).
	hash := sha256.Sum256([]byte(name))
	suffix := hex.EncodeToString(hash[:4])
	return name[:128-9] + "_" + suffix
}

// mongoDialer adapts a dial function to the mongo-driver's Dialer interface.
type mongoDialer struct {
	dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *mongoDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialFunc(ctx, network, addr)
}
