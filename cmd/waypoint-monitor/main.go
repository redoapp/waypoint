package main

import (
	"context"
	"flag"
	"log/slog"
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

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Address,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		logger.Error("redis connection failed", "error", err)
		os.Exit(1)
	}
	defer rdb.Close()

	store := monitor.NewStore(rdb, cfg.Redis.KeyPrefix)

	// Start tsnet + SSH TUI if enabled.
	if cfg.SSH.Enabled {
		tsSrv := &tsnet.Server{
			Hostname: cfg.Tailscale.Hostname,
			Dir:      cfg.Tailscale.StateDir,
		}
		if authKey := os.Getenv("TS_AUTHKEY"); authKey != "" {
			tsSrv.AuthKey = authKey
		}
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

		sshLn, err := tsSrv.Listen("tcp", cfg.SSH.Listen)
		if err != nil {
			logger.Error("ssh listen failed", "error", err)
			os.Exit(1)
		}

		logger.Info("starting SSH TUI", "hostname", cfg.Tailscale.Hostname, "listen", cfg.SSH.Listen)
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
