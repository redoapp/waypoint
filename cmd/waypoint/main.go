package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/google/uuid"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/config"
	"github.com/redoapp/waypoint/internal/heartbeat"
	"github.com/redoapp/waypoint/internal/metrics"
	"github.com/redoapp/waypoint/internal/provision"
	"github.com/redoapp/waypoint/internal/proxy"
	"github.com/redoapp/waypoint/internal/restrict"
	"tailscale.com/tsnet"
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

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, *configPath, logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, configPath string, logger *slog.Logger) error {
	return runServer(ctx, configPath, logger, nil)
}

// runServer starts waypoint. If afterTSStart is non-nil, it is called after the
// tsnet server connects but before listeners are created. Tests use this to set
// node tags on the test control plane.
func runServer(ctx context.Context, configPath string, logger *slog.Logger, afterTSStart func(*tsnet.Server) error) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Metrics.
	m, err := metrics.New(ctx, cfg.Metrics)
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

	lc, err := srv.LocalClient()
	if err != nil {
		return fmt.Errorf("local client: %w", err)
	}

	// Track active connections for graceful shutdown.
	var wg sync.WaitGroup
	var listeners []net.Listener

	revalInterval := cfg.Revalidation.IntervalDuration()

	// Start listeners.
	for _, lCfg := range cfg.Listeners {
		lCfg := lCfg
		mode := strings.ToLower(lCfg.Mode)

		var ln net.Listener
		if lCfg.Service != "" {
			port, err := lCfg.ListenPort()
			if err != nil {
				return fmt.Errorf("invalid listen port for service %s: %w", lCfg.Name, err)
			}
			svcLn, err := srv.ListenService(lCfg.Service, tsnet.ServiceModeTCP{
				Port:                 port,
				PROXYProtocolVersion: 2,
			})
			if err != nil {
				return fmt.Errorf("listen service %s (%s): %w", lCfg.Name, lCfg.Service, err)
			}
			logger.Info("registered tailscale service", "name", lCfg.Name, "service", lCfg.Service, "fqdn", svcLn.FQDN)
			ln = &proxyproto.Listener{Listener: svcLn}
		} else {
			var err error
			ln, err = srv.Listen("tcp", lCfg.Listen)
			if err != nil {
				return fmt.Errorf("listen %s (%s): %w", lCfg.Name, lCfg.Listen, err)
			}
		}
		listeners = append(listeners, ln)

		var dialer func(ctx context.Context, network, addr string) (net.Conn, error)
		if lCfg.BackendViaTailscale {
			dialer = srv.Dial
		}

		switch mode {
		case "tcp":
			p := &proxy.TCPProxy{
				Backend:      lCfg.Backend,
				Name:         lCfg.Name,
				Auth:         &proxy.TailscaleAuthorizer{LC: lc},
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

			provisioner := provision.NewProvisioner(
				lCfg.Postgres.AdminUser,
				lCfg.Postgres.AdminPassword,
				lCfg.Postgres.AdminDatabase,
				lCfg.Backend,
				lCfg.Postgres.UserPrefix,
				store,
				logger.With("component", "provisioner", "listener", lCfg.Name),
			)

			p := &proxy.PostgresProxy{
				Backend:       lCfg.Backend,
				Name:          lCfg.Name,
				Auth:          &proxy.TailscaleAuthorizer{LC: lc},
				Tracker:       tracker,
				Provisioner:   provisioner,
				Metrics:       m,
				PGConfig:      lCfg.Postgres,
				RevalInterval: revalInterval,
				Logger:        logger.With("listener", lCfg.Name),
				Dialer:        dialer,
				BytesRead:     &bytesRead,
				BytesWritten:  &bytesWritten,
			}
			go acceptLoop(ctx, &wg, ln, p.HandleConn, logger.With("listener", lCfg.Name))
		}

		m.SystemListeners.Add(ctx, 1, m.Attrs("waypoint.system.listeners"))
		logger.Info("listening", "name", lCfg.Name, "addr", lCfg.Listen, "mode", mode, "backend", lCfg.Backend)
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
