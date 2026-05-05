package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/mongowire"
)

func TestMongoAcceptClientTLSRequireCapturesSNI(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	setPipeDeadline(t, server, client)

	p := &MongoDBProxy{
		ClientTLSMode: config.TLSRequire,
		ClientTLS:     testMongoServerTLSConfig(t),
	}

	clientErr := make(chan error, 1)
	go func() {
		tlsClient := tls.Client(client, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "mongo.example.com",
		})
		if err := tlsClient.Handshake(); err != nil {
			clientErr <- err
			return
		}
		hello, err := mongowire.BuildHelloCommand("admin")
		if err != nil {
			clientErr <- err
			return
		}
		clientErr <- mongowire.WriteMessage(tlsClient, hello)
	}()

	accepted, sni, err := p.acceptClientTLS(server)
	if err != nil {
		t.Fatalf("acceptClientTLS: %v", err)
	}
	if sni != "mongo.example.com" {
		t.Fatalf("sni = %q, want mongo.example.com", sni)
	}

	assertReadHello(t, accepted)
	if err := <-clientErr; err != nil {
		t.Fatalf("client: %v", err)
	}
}

func TestMongoAcceptClientTLSOptionalAllowsPlaintext(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	setPipeDeadline(t, server, client)

	p := &MongoDBProxy{
		ClientTLSMode: config.TLSOptional,
		ClientTLS:     testMongoServerTLSConfig(t),
	}

	clientErr := make(chan error, 1)
	go func() {
		hello, err := mongowire.BuildHelloCommand("admin")
		if err != nil {
			clientErr <- err
			return
		}
		clientErr <- mongowire.WriteMessage(client, hello)
	}()

	accepted, sni, err := p.acceptClientTLS(server)
	if err != nil {
		t.Fatalf("acceptClientTLS: %v", err)
	}
	if sni != "" {
		t.Fatalf("sni = %q, want empty", sni)
	}

	assertReadHello(t, accepted)
	if err := <-clientErr; err != nil {
		t.Fatalf("client: %v", err)
	}
}

func TestMongoBackendTLSWrapsWireConnection(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	setPipeDeadline(t, server, client)

	serverErr := make(chan error, 1)
	go func() {
		tlsServer := tls.Server(server, testMongoServerTLSConfig(t))
		if err := tlsServer.Handshake(); err != nil {
			serverErr <- err
			return
		}
		serverErr <- readHello(tlsServer)
	}()

	backendConn, err := upgradeMongoBackendTLS(client, "mongo.example.com:27017")
	if err != nil {
		t.Fatalf("upgradeMongoBackendTLS: %v", err)
	}

	hello, err := mongowire.BuildHelloCommand("admin")
	if err != nil {
		t.Fatalf("build hello: %v", err)
	}
	if err := mongowire.WriteMessage(backendConn, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestMongoTopologySNIRewritesAdvertiseHostAndPreservesPorts(t *testing.T) {
	if got := topologyAddrWithSNI("waypoint-db:27017", "mongo.example.com"); got != "mongo.example.com:27017" {
		t.Fatalf("topologyAddrWithSNI = %q", got)
	}

	topologyMap := map[string]string{
		"mongo1.internal:27017": "waypoint-db:27017",
		"mongo2.internal:27017": "waypoint-db:27018",
	}
	rewritten := topologyMapWithSNI(topologyMap, "mongo.example.com")
	if rewritten["mongo1.internal:27017"] != "mongo.example.com:27017" {
		t.Fatalf("mongo1 map = %q", rewritten["mongo1.internal:27017"])
	}
	if rewritten["mongo2.internal:27017"] != "mongo.example.com:27018" {
		t.Fatalf("mongo2 map = %q", rewritten["mongo2.internal:27017"])
	}
}

func assertReadHello(t *testing.T, conn net.Conn) {
	t.Helper()

	if err := readHello(conn); err != nil {
		t.Fatal(err)
	}
}

func readHello(conn net.Conn) error {
	msg, err := mongowire.ReadMessage(conn)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}
	_, doc, err := mongowire.ParseOpMsgBody(msg.Body)
	if err != nil {
		return fmt.Errorf("parse message: %w", err)
	}
	cmd, err := mongowire.CommandName(doc)
	if err != nil {
		return fmt.Errorf("command name: %w", err)
	}
	if cmd != "hello" {
		return fmt.Errorf("command = %q, want hello", cmd)
	}
	return nil
}

func setPipeDeadline(t *testing.T, conns ...net.Conn) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range conns {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}
}

func testMongoServerTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "mongo.example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"mongo.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
			Leaf:        tmpl,
		}},
		MinVersion: tls.VersionTLS12,
	}
}
