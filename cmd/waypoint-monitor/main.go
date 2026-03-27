package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/redoapp/waypoint/internal/admin"
	"github.com/redoapp/waypoint/internal/monitor"
	"tailscale.com/tsnet"
)

func main() {
	configPath := flag.String("config", "waypoint-monitor.toml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	opts := &redis.Options{
		Addr:     cfg.Redis.Address,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}
	if cfg.Redis.TLS {
		opts.TLSConfig = &tls.Config{}
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Error("redis connection failed", "error", err)
		os.Exit(1)
	}
	defer rdb.Close()

	store := monitor.NewStore(rdb, cfg.Redis.KeyPrefix)

	// Start tsnet + SSH TUI if enabled.
	if cfg.SSH.Enabled {
		tsSrv := new(tsnet.Server)
		cfg.Tailscale.Apply(tsSrv)
		if err := tsSrv.Start(); err != nil {
			logger.Error("tsnet start failed", "error", err)
			os.Exit(1)
		}
		defer tsSrv.Close()

		lc, err := tsSrv.LocalClient()
		if err != nil {
			logger.Error("tsnet local client failed", "error", err)
			os.Exit(1)
		}

		hostKeyPath := cfg.SSH.HostKey
		if hostKeyPath == "" {
			hostKeyPath = filepath.Join(cfg.Tailscale.StateDir, "ssh_host_ed25519_key")
		}

		adminSrv, err := admin.New(lc, store, logger, hostKeyPath)
		if err != nil {
			logger.Error("admin server init failed", "error", err)
			os.Exit(1)
		}

		var sshLn net.Listener
		if cfg.SSH.Service != "" {
			port, err := cfg.sshListenPort()
			if err != nil {
				logger.Error("invalid ssh listen port for service", "error", err)
				os.Exit(1)
			}
			svcLn, err := tsSrv.ListenService(cfg.SSH.Service, tsnet.ServiceModeTCP{Port: port})
			if err != nil {
				logger.Error("ssh listen service failed", "service", cfg.SSH.Service, "error", err)
				os.Exit(1)
			}
			sshLn = svcLn
			logger.Info("starting SSH TUI (service)", "service", cfg.SSH.Service, "fqdn", svcLn.FQDN)
		} else {
			var err error
			sshLn, err = tsSrv.Listen("tcp", cfg.SSH.Listen)
			if err != nil {
				logger.Error("ssh listen failed", "error", err)
				os.Exit(1)
			}
			logger.Info("starting SSH TUI", "hostname", cfg.Tailscale.Hostname, "listen", cfg.SSH.Listen)
		}
		go adminSrv.Serve(ctx, sshLn)
	}

	h, err := newHandlers(store, logger)
	if err != nil {
		logger.Error("failed to initialize handlers", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	h.registerRoutes(mux)

	server := &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	logger.Info("starting monitor", "addr", cfg.Listen)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	logger.Info("shutdown complete")
}
