package tsdns

import (
	"context"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestMatchRoute(t *testing.T) {
	routes := map[string][]string{
		"example.internal":     {"10.0.0.1"},
		"cockroachlabs.cloud":  {"10.0.0.2", "10.0.0.3"},
		"sub.example.internal": {"10.0.0.4"},
	}

	tests := []struct {
		name     string
		fqdn     string
		wantOK   bool
		wantAddr string // first resolver if match
	}{
		{"exact match", "example.internal.", true, "10.0.0.1"},
		{"subdomain match", "db.example.internal.", true, "10.0.0.1"},
		{"deeper subdomain", "a.b.example.internal.", true, "10.0.0.1"},
		{"longest match wins", "foo.sub.example.internal.", true, "10.0.0.4"},
		{"no match", "google.com.", false, ""},
		{"partial no match", "notexample.internal.", false, ""},
		{"case insensitive", "DB.Example.Internal.", true, "10.0.0.1"},
		{"no trailing dot", "db.example.internal", true, "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvers, ok := matchRoute(tt.fqdn, routes)
			if ok != tt.wantOK {
				t.Fatalf("matchRoute(%q) ok = %v, want %v", tt.fqdn, ok, tt.wantOK)
			}
			if ok && resolvers[0] != tt.wantAddr {
				t.Fatalf("matchRoute(%q) resolver = %s, want %s", tt.fqdn, resolvers[0], tt.wantAddr)
			}
		})
	}
}

func TestForwardQuery(t *testing.T) {
	// Start a mock UDP DNS server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := buildTestResponse(buf[:n])
			if resp != nil {
				pc.WriteTo(resp, addr)
			}
		}
	}()

	ctx := context.Background()
	listenPacket := func(network, addr string) (net.PacketConn, error) {
		return net.ListenPacket(network, "127.0.0.1:0")
	}

	raw, err := ForwardQuery(ctx, listenPacket, pc.LocalAddr().String(), "test.example.", "A")
	if err != nil {
		t.Fatalf("ForwardQuery: %v", err)
	}

	// Parse the response.
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		t.Fatal(err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	ans, err := parser.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(ans) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(ans))
	}
	a, ok := ans[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("expected A record, got %T", ans[0].Body)
	}
	if a.A != [4]byte{10, 0, 0, 42} {
		t.Fatalf("expected 10.0.0.42, got %v", a.A)
	}
}

func TestRoutedQueryFunc(t *testing.T) {
	// Mock UDP DNS server.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := buildTestResponse(buf[:n])
			if resp != nil {
				pc.WriteTo(resp, addr)
			}
		}
	}()

	listenPacket := func(network, addr string) (net.PacketConn, error) {
		return net.ListenPacket(network, "127.0.0.1:0")
	}

	routes := map[string][]string{
		"example.internal": {pc.LocalAddr().String()},
	}

	fallbackCalled := false
	fallback := func(ctx context.Context, name, qtype string) ([]byte, error) {
		fallbackCalled = true
		return []byte("fallback"), nil
	}

	qf := NewRoutedQueryFunc(fallback, listenPacket, routes)
	ctx := context.Background()

	// Should route through forwarder.
	raw, err := qf(ctx, "db.example.internal.", "A")
	if err != nil {
		t.Fatalf("routed query: %v", err)
	}
	if fallbackCalled {
		t.Fatal("expected forwarder, got fallback")
	}

	// Verify the response parses.
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		t.Fatal(err)
	}

	// Should fall back for non-matching domain.
	_, err = qf(ctx, "google.com.", "A")
	if err != nil {
		t.Fatalf("fallback query: %v", err)
	}
	if !fallbackCalled {
		t.Fatal("expected fallback to be called")
	}
}

// buildTestResponse returns a DNS A response with 10.0.0.42 for any query.
func buildTestResponse(query []byte) []byte {
	var parser dnsmessage.Parser
	hdr, err := parser.Start(query)
	if err != nil {
		return nil
	}
	q, err := parser.Question()
	if err != nil {
		return nil
	}
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       hdr.ID,
			Response: true,
		},
		Questions: []dnsmessage.Question{q},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			},
			Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 42}},
		}},
	}
	packed, _ := resp.Pack()
	return packed
}
