package tsdns

import (
	"context"
	"errors"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// buildDNSResponse constructs a raw DNS response with the given A records.
func buildDNSResponse(name string, ips ...net.IP) []byte {
	dnsName, _ := dnsmessage.NewName(name + ".")
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{
			{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
	}
	for _, ip := range ips {
		ip4 := ip.To4()
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsName,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   300,
			},
			Body: &dnsmessage.AResource{A: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}},
		})
	}
	packed, _ := msg.Pack()
	return packed
}

func TestParseARecords_SingleIP(t *testing.T) {
	raw := buildDNSResponse("example.com", net.ParseIP("10.77.1.50"))
	ips, err := parseARecords(raw, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "10.77.1.50" {
		t.Fatalf("expected [10.77.1.50], got %v", ips)
	}
}

func TestParseARecords_MultipleIPs(t *testing.T) {
	raw := buildDNSResponse("db.example.com",
		net.ParseIP("10.77.1.50"),
		net.ParseIP("10.77.1.51"),
		net.ParseIP("10.77.1.52"),
	)
	ips, err := parseARecords(raw, "db.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 3 {
		t.Fatalf("expected 3 IPs, got %d: %v", len(ips), ips)
	}
}

func TestParseARecords_NoRecords(t *testing.T) {
	// Response with no answers.
	dnsName, _ := dnsmessage.NewName("missing.example.com.")
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{
			{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
	}
	raw, _ := msg.Pack()
	_, err := parseARecords(raw, "missing.example.com")
	if err == nil {
		t.Fatal("expected error for empty response")
	}
}

func TestLookupHost_AddsFQDN(t *testing.T) {
	var queriedName string
	query := func(_ context.Context, name, _ string) ([]byte, error) {
		queriedName = name
		return buildDNSResponse("example.com", net.ParseIP("1.2.3.4")), nil
	}

	_, err := LookupHost(context.Background(), query, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if queriedName != "example.com." {
		t.Fatalf("expected FQDN with trailing dot, got %q", queriedName)
	}
}

func TestLookupHost_AlreadyFQDN(t *testing.T) {
	var queriedName string
	query := func(_ context.Context, name, _ string) ([]byte, error) {
		queriedName = name
		return buildDNSResponse("example.com", net.ParseIP("1.2.3.4")), nil
	}

	_, err := LookupHost(context.Background(), query, "example.com.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if queriedName != "example.com." {
		t.Fatalf("expected unchanged FQDN, got %q", queriedName)
	}
}

func TestLookupHost_QueryError(t *testing.T) {
	query := func(_ context.Context, _, _ string) ([]byte, error) {
		return nil, errors.New("dns failed")
	}

	_, err := LookupHost(context.Background(), query, "example.com")
	if err == nil || err.Error() != "dns failed" {
		t.Fatalf("expected dns failed error, got %v", err)
	}
}

func TestNewDialer_IPPassthrough(t *testing.T) {
	var dialedAddr string
	tsDial := func(_ context.Context, network, addr string) (net.Conn, error) {
		dialedAddr = addr
		return nil, errors.New("mock dial")
	}
	query := func(_ context.Context, _, _ string) ([]byte, error) {
		t.Fatal("query should not be called for IP addresses")
		return nil, nil
	}

	dial := NewDialer(tsDial, query)
	dial(context.Background(), "tcp", "10.77.1.50:26257")

	if dialedAddr != "10.77.1.50:26257" {
		t.Fatalf("expected IP passthrough, got %q", dialedAddr)
	}
}

func TestNewDialer_HostnameResolution(t *testing.T) {
	var dialedAddr string
	tsDial := func(_ context.Context, network, addr string) (net.Conn, error) {
		dialedAddr = addr
		return nil, errors.New("mock dial")
	}
	query := func(_ context.Context, name, _ string) ([]byte, error) {
		return buildDNSResponse("db.example.com", net.ParseIP("10.77.1.50")), nil
	}

	dial := NewDialer(tsDial, query)
	dial(context.Background(), "tcp", "db.example.com:26257")

	if dialedAddr != "10.77.1.50:26257" {
		t.Fatalf("expected resolved IP in dial, got %q", dialedAddr)
	}
}

func TestNewDialer_DNSFailure(t *testing.T) {
	tsDial := func(_ context.Context, _, _ string) (net.Conn, error) {
		t.Fatal("dial should not be called on DNS failure")
		return nil, nil
	}
	query := func(_ context.Context, _, _ string) ([]byte, error) {
		return nil, errors.New("no such host")
	}

	dial := NewDialer(tsDial, query)
	_, err := dial(context.Background(), "tcp", "bad.example.com:26257")

	if err == nil {
		t.Fatal("expected error")
	}
}
