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

func buildSRVDNSResponse(name string, records ...SRVRecord) []byte {
	dnsName, _ := dnsmessage.NewName(name + ".")
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{
			{Name: dnsName, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET},
		},
	}
	for _, record := range records {
		target, _ := dnsmessage.NewName(record.Target + ".")
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

func TestParseSRVRecords(t *testing.T) {
	raw := buildSRVDNSResponse("_mongodb._tcp.cluster.example.com",
		SRVRecord{Target: "mongo1.example.com", Port: 27017, Priority: 10, Weight: 20},
		SRVRecord{Target: "mongo2.example.com", Port: 27018, Priority: 10, Weight: 30},
	)
	records, err := parseSRVRecords(raw, "_mongodb._tcp.cluster.example.com")
	if err != nil {
		t.Fatalf("parseSRVRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records len = %d, want 2", len(records))
	}
	if records[0].Target != "mongo1.example.com" || records[0].Port != 27017 {
		t.Fatalf("records[0] = %+v", records[0])
	}
	if records[1].Target != "mongo2.example.com" || records[1].Port != 27018 {
		t.Fatalf("records[1] = %+v", records[1])
	}
}

func TestLookupSRV_AddsFQDN(t *testing.T) {
	var queriedName, queriedType string
	query := func(_ context.Context, name, qtype string) ([]byte, error) {
		queriedName = name
		queriedType = qtype
		return buildSRVDNSResponse("_mongodb._tcp.cluster.example.com",
			SRVRecord{Target: "mongo1.example.com", Port: 27017},
		), nil
	}

	_, err := LookupSRV(context.Background(), query, "_mongodb._tcp.cluster.example.com")
	if err != nil {
		t.Fatalf("LookupSRV: %v", err)
	}
	if queriedName != "_mongodb._tcp.cluster.example.com." {
		t.Fatalf("queried name = %q", queriedName)
	}
	if queriedType != "SRV" {
		t.Fatalf("queried type = %q, want SRV", queriedType)
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
