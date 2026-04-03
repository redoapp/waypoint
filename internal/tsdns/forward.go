package tsdns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DialFunc dials a network connection, matching tsnet.Server.Dial's signature.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ForwardQuery builds a DNS query for fqdn/qtype, sends it to resolver via
// dial (which routes through Tailscale's userspace network), and returns the
// raw DNS response bytes.
func ForwardQuery(ctx context.Context, dial DialFunc, resolver, fqdn, qtype string) ([]byte, error) {
	// Build the DNS query.
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS name %q: %w", fqdn, err)
	}

	var dnsType dnsmessage.Type
	switch qtype {
	case "A":
		dnsType = dnsmessage.TypeA
	case "AAAA":
		dnsType = dnsmessage.TypeAAAA
	case "CNAME":
		dnsType = dnsmessage.TypeCNAME
	case "TXT":
		dnsType = dnsmessage.TypeTXT
	case "SRV":
		dnsType = dnsmessage.TypeSRV
	case "MX":
		dnsType = dnsmessage.TypeMX
	default:
		return nil, fmt.Errorf("unsupported query type %q", qtype)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsType,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}

	// Ensure resolver has a port.
	if _, _, splitErr := net.SplitHostPort(resolver); splitErr != nil {
		resolver = net.JoinHostPort(resolver, "53")
	}

	slog.Debug("forwarding DNS query", "fqdn", fqdn, "qtype", qtype, "resolver", resolver)

	conn, err := dial(ctx, "udp", resolver)
	if err != nil {
		return nil, fmt.Errorf("dial resolver %s: %w", resolver, err)
	}
	defer conn.Close()

	// Always set a deadline: use context deadline or default 15s.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("write DNS query: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read DNS response from %s for %s: %w", resolver, fqdn, err)
	}

	slog.Debug("DNS query resolved", "fqdn", fqdn, "resolver", resolver, "response_bytes", n)
	return buf[:n], nil
}

// matchRoute finds the longest matching route suffix for name among routes.
// Route keys are domain suffixes (e.g. "example.internal"). The name should be
// an FQDN with trailing dot.
func matchRoute(name string, routes map[string][]string) (resolvers []string, ok bool) {
	// Normalize: remove trailing dot for matching.
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)

	var bestKey string
	for suffix := range routes {
		s := strings.ToLower(suffix)
		if name == s || strings.HasSuffix(name, "."+s) {
			if len(s) > len(bestKey) {
				bestKey = suffix
			}
		}
	}
	if bestKey == "" {
		return nil, false
	}
	return routes[bestKey], true
}

// NewRoutedQueryFunc returns a QueryFunc that routes DNS queries matching
// configured route suffixes through dial (Tailscale userspace network) and
// falls back to fallback (typically lc.QueryDNS) for everything else.
func NewRoutedQueryFunc(fallback QueryFunc, dial DialFunc, routes map[string][]string) QueryFunc {
	if len(routes) == 0 {
		return fallback
	}
	return func(ctx context.Context, name, qtype string) ([]byte, error) {
		resolvers, ok := matchRoute(name, routes)
		if !ok || len(resolvers) == 0 {
			slog.Debug("DNS query using fallback (no route match)", "name", name, "qtype", qtype)
			return fallback(ctx, name, qtype)
		}
		slog.Debug("DNS query matched route", "name", name, "qtype", qtype, "resolvers", resolvers)
		// Try each resolver; return first success.
		var lastErr error
		for _, r := range resolvers {
			resp, err := ForwardQuery(ctx, dial, r, name, qtype)
			if err == nil {
				return resp, nil
			}
			slog.Warn("DNS resolver failed", "name", name, "resolver", r, "error", err)
			lastErr = err
		}
		return nil, fmt.Errorf("all resolvers failed for %s: %w", name, lastErr)
	}
}
