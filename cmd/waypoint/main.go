package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"

	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/heartbeat"
	"github.com/redoapp/waypoint/internal/logging"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/proxy"
	"github.com/redoapp/waypoint/internal/restrict"
	"github.com/redoapp/waypoint/internal/tsdns"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine/netstack"
)

var (
	activeConns  atomic.Int64
	totalConns   atomic.Int64
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
)

func main() {
	configPath := flag.String("config", "waypoint.toml", "path to config file")
	flag.Parse()

	var levelVar slog.LevelVar
	levelVar.Set(slog.LevelInfo)
	if envLevel := os.Getenv("WAYPOINT_LOG_LEVEL"); envLevel != "" {
		if l, err := logging.ParseLevel(envLevel); err == nil {
			levelVar.Set(l)
		}
	}
	logger := slog.New(logging.NewOTelHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: &levelVar})))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, *configPath, logger, &levelVar); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string, logger *slog.Logger, levelVar *slog.LevelVar) error {
	return runServer(ctx, configPath, logger, levelVar, nil)
}

// runServer starts waypoint. If afterTSStart is non-nil, it is called after the
// tsnet server connects but before listeners are created. Tests use this to set
// node tags on the test control plane.
func runServer(ctx context.Context, configPath string, logger *slog.Logger, levelVar *slog.LevelVar, afterTSStart func(*tsnet.Server) error) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if levelVar != nil {
		level, err := logging.ResolveLevel(os.Getenv("WAYPOINT_LOG_LEVEL"), cfg.LogLevel, slog.LevelInfo)
		if err != nil {
			logger.Warn("invalid log level in config, using info", "error", err)
			level = slog.LevelInfo
		}
		levelVar.Set(level)
		logger.Debug("log level configured", "level", level.String())
	}

	// Metrics.
	m, err := metrics.New(ctx, cfg.Metrics, logger)
	if err != nil {
		return fmt.Errorf("initialize metrics: %w", err)
	}
	defer m.Shutdown(ctx)

	// Redis client.
	redisAddr := cfg.Redis.Address
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	opts := &redis.Options{
		Addr:     redisAddr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}
	if cfg.Redis.TLS {
		opts.TLSConfig = &tls.Config{}
	}
	rdb := redis.NewClient(opts)

	redisServiceName := cfg.Redis.ServiceName
	if redisServiceName == "" {
		redisServiceName = "redis"
	}
	if err := redisotel.InstrumentTracing(rdb,
		redisotel.WithAttributes(attribute.String("peer.service", redisServiceName)),
	); err != nil {
		return fmt.Errorf("redis otel tracing: %w", err)
	}
	if err := redisotel.InstrumentMetrics(rdb); err != nil {
		return fmt.Errorf("redis otel metrics: %w", err)
	}

	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis connection: %w", err)
	}
	defer rdb.Close()

	store := restrict.NewRedisStore(rdb, cfg.Redis.KeyPrefix, m)
	tracker := restrict.NewTracker(store, m, logger)

	// Heartbeat publisher.
	instanceID := uuid.New().String()
	go heartbeat.Run(ctx, heartbeat.Config{
		InstanceID: instanceID,
		Client:     rdb,
		KeyPrefix:  cfg.Redis.KeyPrefix,
		Hostname:   cfg.Tailscale.Hostname,
		Listeners:  cfg.Listeners,
		StatsFunc: func() heartbeat.Stats {
			return heartbeat.Stats{
				ActiveConns:  activeConns.Load(),
				TotalConns:   totalConns.Load(),
				BytesRead:    bytesRead.Load(),
				BytesWritten: bytesWritten.Load(),
			}
		},
		Logger: logger.With("component", "heartbeat"),
	})
	logger.Info("heartbeat started", "instance_id", instanceID)

	// tsnet server.
	srv := new(tsnet.Server)
	cfg.Tailscale.Apply(srv)

	if err := srv.Start(); err != nil {
		return fmt.Errorf("tsnet start: %w", err)
	}
	defer srv.Close()

	if afterTSStart != nil {
		if err := afterTSStart(srv); err != nil {
			return fmt.Errorf("after tsnet start: %w", err)
		}
	}

	// Patch tsnet's flow handlers so outbound connections to subnet-routed
	// IPs work. By default, tsnet returns (nil, true) for flows with no
	// local listener, which tells netstack to reject them. We change this
	// to (nil, false) so netstack falls through to its default forwarding
	// behavior (enabled by ProcessSubnets=true).
	if nsImpl, ok := srv.Sys().Netstack.Get().(*netstack.Impl); ok {
		origTCP := nsImpl.GetTCPHandlerForFlow
		nsImpl.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (func(net.Conn), bool) {
			handler, intercept := origTCP(src, dst)
			if intercept && handler == nil {
				return nil, false
			}
			return handler, intercept
		}
		origUDP := nsImpl.GetUDPHandlerForFlow
		nsImpl.GetUDPHandlerForFlow = func(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
			handler, intercept := origUDP(src, dst)
			if intercept && handler == nil {
				return nil, false
			}
			return handler, intercept
		}
		logger.Info("patched netstack flow handlers for subnet route access")
	} else {
		logger.Warn("could not patch netstack flow handlers: type assertion failed")
	}

	lc, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	// Accept subnet routes advertised by other nodes so we can reach
	// resources (e.g. DNS resolvers) behind subnet routers.
	updatedPrefs, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		RouteAllSet: true,
		Prefs:       ipn.Prefs{RouteAll: true},
	})
	if err != nil {
		return fmt.Errorf("enable accept-routes: %w", err)
	}
	logger.Info("subnet routes accepted", "route_all", updatedPrefs.RouteAll)

	// Wait for the node to reach Running state before setting up listeners,
	// so subnet routes are available for DNS resolution and backend dialing.
	logger.Info("waiting for tailscale to reach Running state")
	for {
		st, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("status check: %w", err)
		}
		if st.BackendState == "Running" {
			logger.Info("tailscale is running")
			break
		}
		logger.Debug("tailscale not ready yet", "state", st.BackendState)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Re-apply EditPrefs now that the node is Running and has a netmap,
	// so authReconfigLocked can actually rebuild the WireGuard config.
	rePrefs, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		RouteAllSet: true,
		Prefs:       ipn.Prefs{RouteAll: true},
	})
	if err != nil {
		logger.Warn("re-apply accept-routes failed", "error", err)
	} else {
		logger.Info("subnet routes re-applied after running", "route_all", rePrefs.RouteAll)
	}

	// Log peer subnet routes.
	st, err := lc.Status(ctx)
	if err != nil {
		logger.Warn("status check for peers failed", "error", err)
	} else {
		for _, peer := range st.Peer {
			if peer.PrimaryRoutes != nil && !peer.PrimaryRoutes.IsNil() && peer.PrimaryRoutes.Len() > 0 {
				routes := make([]string, 0, peer.PrimaryRoutes.Len())
				for i := range peer.PrimaryRoutes.Len() {
					routes = append(routes, peer.PrimaryRoutes.At(i).String())
				}
				logger.Info("peer with subnet routes",
					"peer", peer.HostName,
					"routes", routes,
					"online", peer.Online,
				)
			}
		}
	}

	// Track active connections for graceful shutdown.
	var wg sync.WaitGroup
	var listeners []net.Listener

	revalInterval := cfg.Revalidation.IntervalDuration()

	// Start listeners.
	for _, lCfg := range cfg.Listeners {
		lCfg := lCfg
		mode := strings.ToLower(lCfg.Mode)

		// Compute dialer/lookupFunc once per listener config (shared across all ports).
		var dialer func(ctx context.Context, network, addr string) (net.Conn, error)
		var lookupFunc func(ctx context.Context, host string) ([]string, error)
		if lCfg.BackendViaTailscale {
			// Work around tailscale/tailscale#5840: tsnet.Server.Dial does
			// not use MagicDNS for split DNS domains. Resolve hostnames
			// via the Tailscale local API (which goes through the full DNS
			// stack including split DNS), then dial the resolved IP.
			//
			// For DNS servers behind subnet routes, lc.QueryDNS's UDP
			// forwarder also fails (uses system stack). We detect these
			// routes from the network map and forward via srv.Dial instead.
			fallbackDNS := func(ctx context.Context, name, qtype string) ([]byte, error) {
				raw, _, err := lc.QueryDNS(ctx, name, qtype)
				return raw, err
			}
			dnsRoutes, routeErr := tsdns.FetchDNSRoutes(ctx, func(ctx context.Context, mask ipn.NotifyWatchOpt) (tsdns.IPNBusWatcher, error) {
				return lc.WatchIPNBus(ctx, mask)
			})
			if routeErr != nil {
				logger.Warn("failed to fetch DNS routes, falling back to QueryDNS only", "error", routeErr)
			}
			// Use ListenPacket (not Dial) so both send and receive stay
			// within gVisor's netstack. srv.Dial for UDP can fall through
			// to a system socket whose responses are delivered to netstack,
			// not the kernel, causing reads to time out.
			v4, _ := srv.TailscaleIPs()
			listenPacket := func(network, addr string) (net.PacketConn, error) {
				return srv.ListenPacket(network, net.JoinHostPort(v4.String(), "0"))
			}
			queryDNS := tsdns.NewRoutedQueryFunc(fallbackDNS, listenPacket, dnsRoutes)
			lookupFunc = tsdns.NewLookupFunc(queryDNS)
			dialer = tsdns.NewDialer(srv.Dial, queryDNS)
		}

		// Expand port mappings. For single-port configs, returns one entry.
		backends := lCfg.ExpandedBackends()

		var mongoProvisioner *provision.MongoProvisioner
		var mongoTopologyMap map[string]string
		if mode == "mongodb" {
			if lCfg.MongoDB == nil {
				return fmt.Errorf("mongodb listener %s requires [listeners.mongodb] config", lCfg.Name)
			}

			mongoPeerService := lCfg.Name
			if lCfg.MongoDB.ServiceName != "" {
				mongoPeerService = lCfg.MongoDB.ServiceName
			}

			mongoProvisioner = provision.NewMongoReplicaSetProvisioner(
				lCfg.MongoDB.AdminUser,
				lCfg.MongoDB.AdminPassword,
				mongoProvisionBackends(lCfg, backends),
				lCfg.MongoDB.ReplicaSet,
				lCfg.MongoDB.AuthDatabase,
				lCfg.MongoDB.UserPrefix,
				mongoPeerService,
				lCfg.BackendTLS,
				store,
				logger.With("component", "mongo-provisioner", "listener", lCfg.Name),
				dialer,
			).WithRedisScope(lCfg.Name)

			mongoTopologyMap, err = buildMongoTopologyMap(lCfg, backends, cfg.Tailscale.Hostname)
			if err != nil {
				return err
			}
		}

		for _, be := range backends {
			be := be

			var ln net.Listener
			var serviceFQDN string
			if lCfg.Service != "" {
				_, portStr, err := net.SplitHostPort(be.Listen)
				if err != nil {
					return fmt.Errorf("invalid listen address for service %s: %w", lCfg.Name, err)
				}
				port64, err := strconv.ParseUint(portStr, 10, 16)
				if err != nil {
					return fmt.Errorf("invalid listen port for service %s: %w", lCfg.Name, err)
				}
				svcLn, err := srv.ListenService(lCfg.Service, tsnet.ServiceModeTCP{
					Port:                 uint16(port64),
					PROXYProtocolVersion: 2,
				})
				if err != nil {
					return fmt.Errorf("listen service %s (%s): %w", lCfg.Name, lCfg.Service, err)
				}
				serviceFQDN = svcLn.FQDN
				logger.Info("registered tailscale service", "name", lCfg.Name, "service", lCfg.Service, "fqdn", svcLn.FQDN, "port", port64)
				ln = &proxyproto.Listener{Listener: svcLn}
			} else {
				var err error
				ln, err = srv.Listen("tcp", be.Listen)
				if err != nil {
					return fmt.Errorf("listen %s (%s): %w", lCfg.Name, be.Listen, err)
				}
			}
			listeners = append(listeners, ln)

			switch mode {
			case "tcp":
				p := &proxy.TCPProxy{
					Backend:      be.Backend,
					Name:         lCfg.Name,
					Auth:         &proxy.TailscaleAuthorizer{LC: lc, Logger: logger.With("listener", lCfg.Name)},
					Tracker:      tracker,
					Metrics:      m,
					Logger:       logger.With("listener", lCfg.Name),
					Dialer:       dialer,
					BytesRead:    &bytesRead,
					BytesWritten: &bytesWritten,
				}
				go acceptLoop(ctx, &wg, ln, p.HandleConn, logger.With("listener", lCfg.Name))

			case "postgres":
				if lCfg.Postgres == nil {
					return fmt.Errorf("postgres listener %s requires [listeners.postgres] config", lCfg.Name)
				}
				clientTLSMode, clientTLSConfig, err := resolvePostgresClientTLS(lCfg, srv, lc, logger.With("listener", lCfg.Name))
				if err != nil {
					return fmt.Errorf("configure client TLS for listener %s: %w", lCfg.Name, err)
				}

				pgPeerService := lCfg.Name
				if lCfg.Postgres.ServiceName != "" {
					pgPeerService = lCfg.Postgres.ServiceName
				}

				provisioner := provision.NewProvisioner(
					lCfg.Postgres.AdminUser,
					lCfg.Postgres.AdminPassword,
					lCfg.Postgres.AdminDatabase,
					be.Backend,
					lCfg.Postgres.UserPrefix,
					lCfg.BackendTLS,
					config.AllowRawSQLResolved(lCfg.Postgres, &cfg.Provisioning),
					pgPeerService,
					store,
					logger.With("component", "provisioner", "listener", lCfg.Name),
					dialer,
					lookupFunc,
				).WithRedisScope(lCfg.Name)

				p := &proxy.PostgresProxy{
					Backend:       be.Backend,
					Name:          lCfg.Name,
					Auth:          &proxy.TailscaleAuthorizer{LC: lc, Logger: logger.With("listener", lCfg.Name)},
					Tracker:       tracker,
					Provisioner:   provisioner,
					Metrics:       m,
					PGConfig:      lCfg.Postgres,
					ClientTLSMode: clientTLSMode,
					ClientTLS:     clientTLSConfig,
					BackendTLS:    lCfg.BackendTLS,
					RevalInterval: revalInterval,
					Logger:        logger.With("listener", lCfg.Name),
					Dialer:        dialer,
					BytesRead:     &bytesRead,
					BytesWritten:  &bytesWritten,
				}
				go acceptLoop(ctx, &wg, ln, p.HandleConn, logger.With("listener", lCfg.Name))

			case "mongodb":
				proxyAddr, err := advertisedAddr(lCfg, be, cfg.Tailscale.Hostname, serviceFQDN)
				if err != nil {
					return fmt.Errorf("mongodb listener %s advertise address: %w", lCfg.Name, err)
				}

				mp := &proxy.MongoDBProxy{
					Backend:       be.Backend,
					Name:          lCfg.Name,
					ListenAddr:    proxyAddr,
					Auth:          &proxy.TailscaleAuthorizer{LC: lc, Logger: logger.With("listener", lCfg.Name)},
					Tracker:       tracker,
					Provisioner:   mongoProvisioner,
					Metrics:       m,
					MongoConfig:   lCfg.MongoDB,
					TopologyMap:   mongoTopologyMap,
					RevalInterval: revalInterval,
					Logger:        logger.With("listener", lCfg.Name),
					Dialer:        dialer,
					BytesRead:     &bytesRead,
					BytesWritten:  &bytesWritten,
				}
				go acceptLoop(ctx, &wg, ln, mp.HandleConn, logger.With("listener", lCfg.Name))
			}

			m.SystemListeners.Add(ctx, 1, m.Attrs("waypoint.system.listeners"))
			logger.Info("listening", "name", lCfg.Name, "addr", be.Listen, "mode", mode, "backend", be.Backend)
		}
	}

	<-ctx.Done()
	logger.Info("shutting down, draining connections...")

	// Close listeners to stop accepting new connections.
	for _, ln := range listeners {
		ln.Close()
	}

	// Wait for active connections to finish.
	wg.Wait()
	logger.Info("shutdown complete")
	return nil
}

func resolvePostgresClientTLS(lCfg config.ListenerConfig, srv *tsnet.Server, lc *local.Client, logger *slog.Logger) (config.PostgresTLSMode, *tls.Config, error) {
	mode := lCfg.EffectivePostgresTLSMode()
	if mode == config.PostgresTLSOff {
		return mode, nil, nil
	}

	var adminCert *tls.Certificate
	if lCfg.CertFile != "" && lCfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(lCfg.CertFile, lCfg.KeyFile)
		if err != nil {
			return "", nil, fmt.Errorf("load cert/key pair: %w", err)
		}
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return "", nil, fmt.Errorf("parse admin certificate: %w", err)
			}
			cert.Leaf = leaf
		}
		adminCert = &cert
	}

	certDomains := tailscaleCertDomains(srv)
	var tailscaleGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if lCfg.EffectiveUseTailscaleTLS() && len(certDomains) > 0 {
		defaultServerName := certDomains[0]
		tailscaleGetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hi == nil {
				hi = &tls.ClientHelloInfo{}
			}
			hello := *hi
			if hello.ServerName == "" {
				hello.ServerName = defaultServerName
			}
			return lc.GetCertificate(&hello)
		}
	}

	if adminCert == nil && tailscaleGetCertificate == nil {
		if mode == config.PostgresTLSRequire {
			return "", nil, fmt.Errorf("tls_mode=require but no usable certificate source is available")
		}
		logger.Warn("client TLS requested but no certificate source is available; downgrading listener to plaintext",
			"mode", mode,
			"listener", lCfg.Name,
		)
		return config.PostgresTLSOff, nil, nil
	}

	return mode, buildPostgresClientTLSConfig(adminCert, tailscaleGetCertificate), nil
}

func tailscaleCertDomains(srv *tsnet.Server) (domains []string) {
	if srv == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			domains = nil
		}
	}()
	return srv.CertDomains()
}

func buildPostgresClientTLSConfig(adminCert *tls.Certificate, tailscaleGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if adminCert != nil {
				if hi == nil || hi.ServerName == "" {
					return adminCert, nil
				}
				if adminCert.Leaf != nil && adminCert.Leaf.VerifyHostname(hi.ServerName) == nil {
					return adminCert, nil
				}
			}
			if tailscaleGetCertificate != nil {
				return tailscaleGetCertificate(hi)
			}
			if adminCert != nil {
				return adminCert, nil
			}
			return nil, fmt.Errorf("no TLS certificate available")
		},
	}
}

func acceptLoop(ctx context.Context, wg *sync.WaitGroup, ln net.Listener, handler func(context.Context, net.Conn), logger *slog.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Error("accept failed", "error", err)
				continue
			}
		}
		wg.Add(1)
		activeConns.Add(1)
		totalConns.Add(1)
		go func() {
			defer wg.Done()
			defer activeConns.Add(-1)
			handler(ctx, conn)
		}()
	}
}

func mongoProvisionBackends(lCfg config.ListenerConfig, backends []config.BackendPair) []string {
	if lCfg.MongoDB == nil || len(lCfg.MongoDB.Members) == 0 {
		return []string{lCfg.Backend}
	}

	seen := make(map[string]bool, len(backends))
	result := make([]string, 0, len(backends))
	for _, be := range backends {
		if be.Backend == "" || seen[be.Backend] {
			continue
		}
		seen[be.Backend] = true
		result = append(result, be.Backend)
	}
	return result
}

func buildMongoTopologyMap(lCfg config.ListenerConfig, backends []config.BackendPair, tailscaleHostname string) (map[string]string, error) {
	if lCfg.MongoDB == nil || len(lCfg.MongoDB.Members) == 0 {
		return nil, nil
	}

	topologyMap := make(map[string]string, len(backends))
	for _, be := range backends {
		advertise, err := advertisedAddr(lCfg, be, tailscaleHostname, "")
		if err != nil {
			return nil, fmt.Errorf("mongodb listener %s member %s advertise address: %w", lCfg.Name, be.Backend, err)
		}
		addTopologyMapAddr(topologyMap, be.Backend, advertise)
	}
	return topologyMap, nil
}

func advertisedAddr(lCfg config.ListenerConfig, be config.BackendPair, tailscaleHostname, serviceFQDN string) (string, error) {
	if be.Advertise != "" {
		return be.Advertise, nil
	}

	_, port, err := net.SplitHostPort(be.Listen)
	if err != nil {
		return "", fmt.Errorf("split listen address %q: %w", be.Listen, err)
	}

	host := strings.TrimSuffix(serviceFQDN, ".")
	if host == "" {
		host = lCfg.Advertise
		if host != "" {
			if advertiseHost, advertisePort, err := net.SplitHostPort(host); err == nil {
				if advertisePort == port {
					return host, nil
				}
				host = advertiseHost
			}
		}
	}
	if host == "" {
		host = tailscaleHostname
	}
	if host == "" {
		return "", fmt.Errorf("no tailscale hostname available")
	}

	return net.JoinHostPort(host, port), nil
}

func addTopologyMapAddr(topologyMap map[string]string, backend, advertise string) {
	if backend == "" || advertise == "" {
		return
	}
	topologyMap[backend] = advertise
	topologyMap[strings.ToLower(backend)] = advertise

	host, port, err := net.SplitHostPort(backend)
	if err != nil {
		return
	}
	topologyMap[net.JoinHostPort(strings.ToLower(host), port)] = advertise
	topologyMap[strings.ToLower(host)+":"+port] = advertise
}
