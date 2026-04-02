// Package tsdns provides DNS resolution through the Tailscale local API.
//
// This works around tailscale/tailscale#5840 where tsnet.Server.Dial
// falls back to the system resolver for non-tailnet names, breaking
// split DNS resolution.
package tsdns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// QueryFunc matches the signature of local.Client.QueryDNS.
type QueryFunc func(ctx context.Context, name, queryType string) ([]byte, error)

// LookupHost resolves a hostname to IP addresses using the provided
// Tailscale DNS query function. The query function should call
// local.Client.QueryDNS (or equivalent) which goes through the full
// Tailscale DNS stack including MagicDNS and split DNS.
func LookupHost(ctx context.Context, query QueryFunc, host string) ([]string, error) {
	// Ensure the name is FQDN (trailing dot).
	fqdn := host
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	raw, err := query(ctx, fqdn, "A")
	if err != nil {
		return nil, err
	}

	return parseARecords(raw, host)
}

// parseARecords extracts IPv4 addresses from a raw DNS response.
func parseARecords(raw []byte, host string) ([]string, error) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		return nil, fmt.Errorf("parse DNS response: %w", err)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("skip questions: %w", err)
	}

	var ips []string
	for {
		hdr, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse answer: %w", err)
		}
		if hdr.Type == dnsmessage.TypeA {
			r, err := parser.AResource()
			if err != nil {
				return nil, fmt.Errorf("parse A record: %w", err)
			}
			ips = append(ips, net.IP(r.A[:]).String())
		} else {
			if err := parser.SkipAnswer(); err != nil {
				return nil, fmt.Errorf("skip answer: %w", err)
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records for %q", host)
	}
	return ips, nil
}

// NewDialer creates a dialer that resolves hostnames through Tailscale's
// DNS stack before dialing via the provided Tailscale dialer. This ensures
// split DNS domains are resolved correctly.
func NewDialer(tsDial func(ctx context.Context, network, addr string) (net.Conn, error), query QueryFunc) func(ctx context.Context, network, addr string) (net.Conn, error) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		return LookupHost(ctx, query, host)
	}
	return newDialerWithLookup(tsDial, lookup)
}

// NewLookupFunc returns a LookupFunc suitable for use with pgx or similar
// libraries that perform DNS resolution separately from dialing.
func NewLookupFunc(query QueryFunc) func(ctx context.Context, host string) ([]string, error) {
	return func(ctx context.Context, host string) ([]string, error) {
		return LookupHost(ctx, query, host)
	}
}

func newDialerWithLookup(tsDial func(ctx context.Context, network, addr string) (net.Conn, error), lookup func(ctx context.Context, host string) ([]string, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return tsDial(ctx, network, addr)
		}
		if net.ParseIP(host) != nil {
			return tsDial(ctx, network, addr)
		}
		ips, err := lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("tailscale DNS lookup %q: %w", host, err)
		}
		return tsDial(ctx, network, net.JoinHostPort(ips[0], port))
	}
}
