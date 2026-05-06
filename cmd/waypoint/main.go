package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/redoapp/waypoint/internal/logging"
	"github.com/redoapp/waypoint/internal/server"
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

	if err := server.Run(ctx, *configPath, logger, &levelVar); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}
