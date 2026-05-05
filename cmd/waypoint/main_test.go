package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"log/slog"

	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/tsdns"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tsnet"
)

func TestBuildPostgresClientTLSConfig_UsesAdminCertForMatchingSNI(t *testing.T) {
	adminCert := mustNamedCertificate(t, "waypoint.redo.run")
	tailscaleCalls := 0
	conf := buildPostgresClientTLSConfig(adminCert, func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		tailscaleCalls++
		return mustNamedCertificate(t, hi.ServerName), nil
	})

	got, err := conf.GetCertificate(&tls.ClientHelloInfo{ServerName: "waypoint.redo.run"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != adminCert {
		t.Fatal("expected admin certificate to be selected")
	}
	if tailscaleCalls != 0 {
		t.Fatalf("expected no tailscale lookup, got %d", tailscaleCalls)
	}
}

func TestBuildPostgresClientTLSConfig_UsesTailscaleCertForDifferentSNI(t *testing.T) {
	adminCert := mustNamedCertificate(t, "waypoint.redo.run")
	tailscaleCert := mustNamedCertificate(t, "waypoint-db.ts.net")
	conf := buildPostgresClientTLSConfig(adminCert, func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hi.ServerName != "waypoint-db.ts.net" {
			t.Fatalf("tailscale lookup saw %q", hi.ServerName)
		}
		return tailscaleCert, nil
	})

	got, err := conf.GetCertificate(&tls.ClientHelloInfo{ServerName: "waypoint-db.ts.net"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != tailscaleCert {
		t.Fatal("expected tailscale certificate to be selected")
	}
}

func TestBuildPostgresClientTLSConfig_NoSNIFallsBackToAdminCert(t *testing.T) {
	adminCert := mustNamedCertificate(t, "waypoint.redo.run")
	tailscaleCalls := 0
	conf := buildPostgresClientTLSConfig(adminCert, func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		tailscaleCalls++
		return mustNamedCertificate(t, "waypoint-db.ts.net"), nil
	})

	got, err := conf.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != adminCert {
		t.Fatal("expected admin certificate fallback")
	}
	if tailscaleCalls != 0 {
		t.Fatalf("expected no tailscale lookup, got %d", tailscaleCalls)
	}
}

func TestBuildPostgresClientTLSConfig_AdminOnlyIgnoresTailscale(t *testing.T) {
	adminCert := mustNamedCertificate(t, "waypoint.redo.run")
	conf := buildPostgresClientTLSConfig(adminCert, nil)

	got, err := conf.GetCertificate(&tls.ClientHelloInfo{ServerName: "waypoint-db.ts.net"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != adminCert {
		t.Fatal("expected admin certificate fallback when tailscale TLS is disabled")
	}
}

func TestBuildPostgresClientTLSConfig_UnknownSNIFallsBackToTailscale(t *testing.T) {
	adminCert := mustNamedCertificate(t, "waypoint.redo.run")
	tailscaleCert := mustNamedCertificate(t, "fallback.ts.net")
	tailscaleCalls := 0
	conf := buildPostgresClientTLSConfig(adminCert, func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		tailscaleCalls++
		if hi.ServerName != "unknown.example.com" {
			t.Fatalf("tailscale lookup saw %q", hi.ServerName)
		}
		return tailscaleCert, nil
	})

	got, err := conf.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != tailscaleCert {
		t.Fatal("expected tailscale certificate fallback")
	}
	if tailscaleCalls != 1 {
		t.Fatalf("expected one tailscale lookup, got %d", tailscaleCalls)
	}
}

func TestResolvePostgresClientTLS_OptionalNoSourcesDowngradesToOff(t *testing.T) {
	lCfg := config.ListenerConfig{
		Name:            "pg",
		Mode:            "postgres",
		PostgresTLSMode: string(config.PostgresTLSOptional),
	}
	mode, tlsConf, err := resolvePostgresClientTLS(lCfg, &tsnet.Server{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("resolvePostgresClientTLS: %v", err)
	}
	if mode != config.PostgresTLSOff {
		t.Fatalf("mode = %q, want %q", mode, config.PostgresTLSOff)
	}
	if tlsConf != nil {
		t.Fatalf("expected nil TLS config, got %v", tlsConf)
	}
}

func TestResolvePostgresClientTLS_RequireNoSourcesFails(t *testing.T) {
	lCfg := config.ListenerConfig{
		Name:            "pg",
		Mode:            "postgres",
		PostgresTLSMode: string(config.PostgresTLSRequire),
	}
	_, _, err := resolvePostgresClientTLS(lCfg, &tsnet.Server{}, nil, discardLogger())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolvePostgresClientTLS_AdminFilesOnly(t *testing.T) {
	certFile, keyFile := mustNamedCertificateFiles(t, "waypoint.redo.run")
	useTailscale := false
	lCfg := config.ListenerConfig{
		Name:            "pg",
		Mode:            "postgres",
		PostgresTLSMode: string(config.PostgresTLSOptional),
		UseTailscaleTLS: &useTailscale,
		CertFile:        certFile,
		KeyFile:         keyFile,
	}
	mode, tlsConf, err := resolvePostgresClientTLS(lCfg, &tsnet.Server{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("resolvePostgresClientTLS: %v", err)
	}
	if mode != config.PostgresTLSOptional {
		t.Fatalf("mode = %q, want %q", mode, config.PostgresTLSOptional)
	}
	if tlsConf == nil || tlsConf.GetCertificate == nil {
		t.Fatal("expected TLS config with GetCertificate")
	}
	got, err := tlsConf.GetCertificate(&tls.ClientHelloInfo{ServerName: "waypoint.redo.run"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil {
		t.Fatal("expected certificate")
	}
}

func TestResolveMongoClientTLS_AdminFilesOnly(t *testing.T) {
	certFile, keyFile := mustNamedCertificateFiles(t, "mongo.example.com")
	useTailscale := false
	lCfg := config.ListenerConfig{
		Name:            "mongo",
		Mode:            "mongodb",
		PostgresTLSMode: string(config.TLSRequire),
		UseTailscaleTLS: &useTailscale,
		CertFile:        certFile,
		KeyFile:         keyFile,
	}
	mode, tlsConf, err := resolveMongoClientTLS(lCfg, &tsnet.Server{}, nil, discardLogger())
	if err != nil {
		t.Fatalf("resolveMongoClientTLS: %v", err)
	}
	if mode != config.TLSRequire {
		t.Fatalf("mode = %q, want %q", mode, config.TLSRequire)
	}
	got, err := tlsConf.GetCertificate(&tls.ClientHelloInfo{ServerName: "mongo.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil {
		t.Fatal("expected certificate")
	}
}

func mustNamedCertificate(t *testing.T, dnsName string) *tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        tmpl,
	}
}

func mustNamedCertificateFiles(t *testing.T, dnsName string) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAdvertisedAddrUsesMemberAdvertise(t *testing.T) {
	got, err := advertisedAddr(config.ListenerConfig{}, config.BackendPair{
		Listen:    ":27017",
		Advertise: "mongo-proxy:27017",
	}, "waypoint-db", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "mongo-proxy:27017" {
		t.Fatalf("advertisedAddr = %q, want mongo-proxy:27017", got)
	}
}

func TestAdvertisedAddrDefaultsToTailscaleHostname(t *testing.T) {
	got, err := advertisedAddr(config.ListenerConfig{}, config.BackendPair{
		Listen: ":27018",
	}, "waypoint-db", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "waypoint-db:27018" {
		t.Fatalf("advertisedAddr = %q, want waypoint-db:27018", got)
	}
}

func TestBuildMongoTopologyMap(t *testing.T) {
	lCfg := config.ListenerConfig{
		Name: "mongo-prod",
		MongoDB: &config.MongoDBAdmin{
			Members: []config.MongoDBMember{
				{Backend: "mongo1.internal:27017", Listen: ":27017", Advertise: "waypoint:27017"},
				{Backend: "mongo2.internal:27017", Listen: ":27018", Advertise: "waypoint:27018"},
			},
		},
	}
	pairs := lCfg.ExpandedBackends()
	topologyMap, err := buildMongoTopologyMap(lCfg, pairs, "waypoint")
	if err != nil {
		t.Fatal(err)
	}
	if topologyMap["mongo1.internal:27017"] != "waypoint:27017" {
		t.Fatalf("mongo1 map = %q", topologyMap["mongo1.internal:27017"])
	}
	if topologyMap["mongo2.internal:27017"] != "waypoint:27018" {
		t.Fatalf("mongo2 map = %q", topologyMap["mongo2.internal:27017"])
	}
}

func TestMaterializeMongoSRVBackends(t *testing.T) {
	lCfg := config.ListenerConfig{
		Name:      "mongo-prod",
		Listen:    ":27017",
		Advertise: "waypoint-db",
		MongoDB: &config.MongoDBAdmin{
			SRV:           "cluster.example.com",
			SRVMaxMembers: 3,
		},
	}
	backends := lCfg.ExpandedBackends()
	query := func(_ context.Context, name, qtype string) ([]byte, error) {
		if name != "_mongodb._tcp.cluster.example.com." {
			t.Fatalf("query name = %q", name)
		}
		if qtype != "SRV" {
			t.Fatalf("query type = %q", qtype)
		}
		return buildTestSRVDNSResponse(t, "_mongodb._tcp.cluster.example.com",
			tsdns.SRVRecord{Target: "mongo2.example.com", Port: 27017, Priority: 10},
			tsdns.SRVRecord{Target: "mongo1.example.com", Port: 27017, Priority: 10},
		), nil
	}

	resolved, err := materializeMongoSRVBackends(context.Background(), lCfg, backends, query)
	if err != nil {
		t.Fatal(err)
	}
	expected := []config.BackendPair{
		{Listen: ":27017", Backend: "mongo1.example.com:27017", Advertise: "waypoint-db"},
		{Listen: ":27018", Backend: "mongo2.example.com:27017", Advertise: "waypoint-db"},
	}
	if len(resolved) != len(expected) {
		t.Fatalf("resolved len = %d, want %d", len(resolved), len(expected))
	}
	for i, want := range expected {
		if resolved[i] != want {
			t.Fatalf("resolved[%d] = %+v, want %+v", i, resolved[i], want)
		}
	}
}

func TestMaterializeMongoSRVBackendsTooManyRecords(t *testing.T) {
	lCfg := config.ListenerConfig{
		Name:   "mongo-prod",
		Listen: ":27017",
		MongoDB: &config.MongoDBAdmin{
			SRV:           "cluster.example.com",
			SRVMaxMembers: 1,
		},
	}
	backends := lCfg.ExpandedBackends()
	query := func(_ context.Context, _, _ string) ([]byte, error) {
		return buildTestSRVDNSResponse(t, "_mongodb._tcp.cluster.example.com",
			tsdns.SRVRecord{Target: "mongo1.example.com", Port: 27017},
			tsdns.SRVRecord{Target: "mongo2.example.com", Port: 27017},
		), nil
	}

	_, err := materializeMongoSRVBackends(context.Background(), lCfg, backends, query)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildMongoTopologyMapWithSRVBackends(t *testing.T) {
	lCfg := config.ListenerConfig{
		Name:      "mongo-prod",
		Advertise: "waypoint-db",
		MongoDB: &config.MongoDBAdmin{
			SRV:           "cluster.example.com",
			SRVMaxMembers: 2,
		},
	}
	backends := []config.BackendPair{
		{Listen: ":27017", Backend: "mongo1.example.com:27017", Advertise: "waypoint-db"},
		{Listen: ":27018", Backend: "mongo2.example.com:27017", Advertise: "waypoint-db"},
	}

	topologyMap, err := buildMongoTopologyMap(lCfg, backends, "waypoint")
	if err != nil {
		t.Fatal(err)
	}
	if topologyMap["mongo1.example.com:27017"] != "waypoint-db:27017" {
		t.Fatalf("mongo1 map = %q", topologyMap["mongo1.example.com:27017"])
	}
	if topologyMap["mongo2.example.com:27017"] != "waypoint-db:27018" {
		t.Fatalf("mongo2 map = %q", topologyMap["mongo2.example.com:27017"])
	}
}

func buildTestSRVDNSResponse(t *testing.T, name string, records ...tsdns.SRVRecord) []byte {
	t.Helper()

	dnsName, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatalf("new name: %v", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{
			{Name: dnsName, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET},
		},
	}
	for _, record := range records {
		target, err := dnsmessage.NewName(record.Target + ".")
		if err != nil {
			t.Fatalf("new target: %v", err)
		}
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsName,
				Type:  dnsmessage.TypeSRV,
				Class: dnsmessage.ClassINET,
				TTL:   300,
			},
			Body: &dnsmessage.SRVResource{
				Priority: record.Priority,
				Weight:   record.Weight,
				Port:     record.Port,
				Target:   target,
			},
		})
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return packed
}
