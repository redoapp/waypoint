package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redoapp/waypoint/internal/logging"
	"github.com/redoapp/waypoint/internal/server"
)

func main() {
	configPath := flag.String("config", "waypoint.toml", "path to config file")
	healthcheckAddress := flag.String("healthcheck-address", "", "exit after checking a TCP backend address")
	healthcheckTimeout := flag.Duration("healthcheck-timeout", time.Second, "TCP backend healthcheck timeout")
	flag.Parse()
	if *healthcheckAddress != "" {
		if err := checkTCPBackend(context.Background(), *healthcheckAddress, *healthcheckTimeout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

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

	if err := server.Run(ctx, *configPath, logger, &levelVar); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func checkTCPBackend(ctx context.Context, address string, timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("healthcheck timeout must be positive")
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("TCP healthcheck %s: %w", address, err)
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("close TCP healthcheck %s: %w", address, err)
	}
	return nil
}
