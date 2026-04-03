package tsdns

import (
	"context"
	"fmt"

	"tailscale.com/ipn"
)

// IPNBusWatcher abstracts the watcher returned by WatchIPNBus so that
// FetchDNSRoutes can be tested without a real Tailscale client.
type IPNBusWatcher interface {
	Next() (ipn.Notify, error)
	Close() error
}

// WatchIPNBusFunc matches the signature of tailscale.com/client/local.Client.WatchIPNBus.
type WatchIPNBusFunc func(ctx context.Context, mask ipn.NotifyWatchOpt) (IPNBusWatcher, error)

// FetchDNSRoutes reads DNS routes from the Tailscale network map via the IPN
// bus. It returns a simplified map of domain suffix → resolver address list.
func FetchDNSRoutes(ctx context.Context, watchIPNBus WatchIPNBusFunc) (map[string][]string, error) {
	w, err := watchIPNBus(ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		return nil, fmt.Errorf("watch IPN bus: %w", err)
	}
	defer w.Close()

	n, err := w.Next()
	if err != nil {
		return nil, fmt.Errorf("read initial netmap: %w", err)
	}

	if n.NetMap == nil {
		return nil, fmt.Errorf("no NetMap in initial notification")
	}

	dnsRoutes := n.NetMap.DNS.Routes
	if len(dnsRoutes) == 0 {
		return nil, nil
	}

	routes := make(map[string][]string, len(dnsRoutes))
	for domain, resolvers := range dnsRoutes {
		var addrs []string
		for _, r := range resolvers {
			if r.Addr != "" {
				addrs = append(addrs, r.Addr)
			}
		}
		// Only include routes with explicit resolvers (empty means MagicDNS handles it).
		if len(addrs) > 0 {
			routes[domain] = addrs
		}
	}

	return routes, nil
}
