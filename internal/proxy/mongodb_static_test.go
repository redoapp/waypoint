package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/redoapp/waypoint/internal/auth"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/mongowire"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/restrict"
)

type mongoStaticTestAuthorizer struct {
	result *auth.AuthResult
	err    error
}

func (a mongoStaticTestAuthorizer) Authorize(context.Context, string, string) (*auth.AuthResult, error) {
	return a.result, a.err
}

func TestMongoStaticCredentialMatchesDatabasePreset(t *testing.T) {
	p := &MongoDBProxy{
		MongoConfig: &config.MongoDBAdmin{
			AuthDatabase: "admin",
			Provision: &config.MongoProvision{
				Mode: config.MongoProvisionStatic,
				StaticUsers: []config.MongoStaticUser{
					{
						Name:        "app-readwrite",
						Username:    "atlas_app_rw",
						Password:    "secret",
						Database:    "app",
						Permissions: []string{"readwrite"},
					},
				},
			},
		},
	}

	cred, err := p.selectStaticCredential(mongoAccess{
		Roles: []provision.MongoRole{{Role: "readWrite", DB: "app"}},
		Grants: []mongoDatabaseGrant{
			{Database: "app", Permissions: []string{"readwrite"}},
		},
	})
	if err != nil {
		t.Fatalf("selectStaticCredential: %v", err)
	}
	if cred.Username != "atlas_app_rw" || cred.AuthDatabase != "admin" {
		t.Fatalf("credential = %+v", cred)
	}
}

func TestMongoStaticCredentialMatchesPermissionOnlyUser(t *testing.T) {
	p := &MongoDBProxy{
		MongoConfig: &config.MongoDBAdmin{
			AuthDatabase: "admin",
			Provision: &config.MongoProvision{
				Mode: config.MongoProvisionStatic,
				StaticUsers: []config.MongoStaticUser{
					{
						Name:        "readonly",
						Username:    "atlas_ro",
						Password:    "secret",
						Permissions: []string{"readonly"},
					},
				},
			},
		},
	}

	cred, err := p.selectStaticCredential(mongoAccess{
		Roles: []provision.MongoRole{
			{Role: "read", DB: "app"},
			{Role: "read", DB: "reporting"},
		},
		Grants: []mongoDatabaseGrant{
			{Database: "app", Permissions: []string{"readonly"}},
			{Database: "reporting", Permissions: []string{"readonly"}},
		},
	})
	if err != nil {
		t.Fatalf("selectStaticCredential: %v", err)
	}
	if cred.Username != "atlas_ro" {
		t.Fatalf("username = %q, want atlas_ro", cred.Username)
	}
}

func TestMongoStaticCredentialRejectsMixedPermissionOnlyUser(t *testing.T) {
	p := &MongoDBProxy{
		MongoConfig: &config.MongoDBAdmin{
			AuthDatabase: "admin",
			Provision: &config.MongoProvision{
				Mode: config.MongoProvisionStatic,
				StaticUsers: []config.MongoStaticUser{
					{
						Name:        "readonly",
						Username:    "atlas_ro",
						Password:    "secret",
						Permissions: []string{"readonly"},
					},
				},
			},
		},
	}

	_, err := p.selectStaticCredential(mongoAccess{
		Roles: []provision.MongoRole{
			{Role: "readWrite", DB: "app"},
			{Role: "read", DB: "reporting"},
		},
		Grants: []mongoDatabaseGrant{
			{Database: "app", Permissions: []string{"readwrite"}},
			{Database: "reporting", Permissions: []string{"readonly"}},
		},
	})
	if err == nil {
		t.Fatal("expected no matching static user")
	}
}

func TestMongoStaticCredentialReadWriteWinsOverReadonlyGrant(t *testing.T) {
	p := &MongoDBProxy{
		Name: "mongo",
		MongoConfig: &config.MongoDBAdmin{
			AuthDatabase: "admin",
			Provision: &config.MongoProvision{
				Mode: config.MongoProvisionStatic,
				StaticUsers: []config.MongoStaticUser{
					{
						Name:        "readonly",
						Username:    "atlas_ro",
						Password:    "ro-secret",
						Permissions: []string{"readonly"},
					},
					{
						Name:        "readwrite",
						Username:    "atlas_rw",
						Password:    "rw-secret",
						Permissions: []string{"readwrite"},
					},
				},
			},
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	result := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		MatchedRules: []auth.CapRule{
			{
				Backends: map[string]auth.BackendCap{
					"mongo": {
						Mongo: &auth.MongoCap{
							Databases: map[string]auth.MongoDBPermissions{
								"app": {Permissions: []string{"readonly"}},
							},
						},
					},
				},
			},
			{
				Backends: map[string]auth.BackendCap{
					"mongo": {
						Mongo: &auth.MongoCap{
							Databases: map[string]auth.MongoDBPermissions{
								"app": {Permissions: []string{"readwrite"}},
							},
						},
					},
				},
			},
		},
	}

	cred, err := p.selectStaticCredential(p.collectAccess(result))
	if err != nil {
		t.Fatalf("selectStaticCredential: %v", err)
	}
	if cred.Username != "atlas_rw" {
		t.Fatalf("username = %q, want atlas_rw", cred.Username)
	}
}

func TestMongoStaticMissingCredentialReturnsClientMessage(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	m := metrics.Noop()
	store := restrict.NewRedisStore(rdb, "mongostatictest:", m)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	result := &auth.AuthResult{
		LoginName: "testuser@example.com",
		NodeName:  "test-node",
		MatchedRules: []auth.CapRule{
			{
				Backends: map[string]auth.BackendCap{
					"mongo": {
						Mongo: &auth.MongoCap{
							Databases: map[string]auth.MongoDBPermissions{
								"app": {Permissions: []string{"readwrite"}},
							},
						},
					},
				},
			},
		},
	}

	p := &MongoDBProxy{
		Name:    "mongo",
		Auth:    mongoStaticTestAuthorizer{result: result},
		Tracker: restrict.NewTracker(store, m, logger),
		Metrics: m,
		MongoConfig: &config.MongoDBAdmin{
			AuthDatabase: "admin",
			Provision: &config.MongoProvision{
				Mode: config.MongoProvisionStatic,
				StaticUsers: []config.MongoStaticUser{
					{
						Name:        "readonly",
						Username:    "atlas_ro",
						Password:    "secret",
						Permissions: []string{"readonly"},
					},
				},
			},
		},
		Logger: logger,
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.HandleConn(context.Background(), serverConn)
	}()

	hello, err := mongowire.BuildHelloCommand("admin")
	if err != nil {
		t.Fatalf("BuildHelloCommand: %v", err)
	}
	if err := mongowire.WriteMessage(clientConn, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	resp, err := mongowire.ReadMessage(clientConn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Header.OpCode != mongowire.OpMsg {
		t.Fatalf("opcode = %d, want OP_MSG", resp.Header.OpCode)
	}
	_, doc, err := mongowire.ParseOpMsgBody(resp.Body)
	if err != nil {
		t.Fatalf("ParseOpMsgBody: %v", err)
	}

	var reply struct {
		OK     float64 `bson:"ok"`
		ErrMsg string  `bson:"errmsg"`
		Code   int32   `bson:"code"`
	}
	if err := bson.Unmarshal(doc, &reply); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if reply.OK != 0 || reply.Code != 18 {
		t.Fatalf("reply = %+v, want auth failure", reply)
	}
	if !strings.Contains(reply.ErrMsg, "no static MongoDB user configured for requested permissions") {
		t.Fatalf("errmsg = %q", reply.ErrMsg)
	}

	<-done
}
