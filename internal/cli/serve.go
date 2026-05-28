// Package cli: serve command.
package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/server"
)

func newServeCmd() *cobra.Command {
	var (
		listen    string
		ttl       int
		rateLimit float64
		rateBurst float64
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the signaling and NAT helper service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(listen, time.Duration(ttl)*time.Second, rateLimit, rateBurst)
		},
	}

	cmd.Flags().StringVarP(&listen, "listen", "l", envOrDefault("HERMOD_LISTEN", "0.0.0.0:4376"), "Bind address (host:port)")
	cmd.Flags().IntVarP(&ttl, "ttl", "T", 600, "Channel TTL in seconds")
	cmd.Flags().Float64Var(&rateLimit, "rate-limit", 5, "Token bucket rate (requests/sec per IP prefix)")
	cmd.Flags().Float64Var(&rateBurst, "rate-burst", 15, "Token bucket burst capacity per IP prefix")

	return cmd
}

func runServe(listenAddr string, ttl time.Duration, rateLimit, rateBurst float64) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Generate server cert on first run
	if cfg.ServerCertPEM == "" || cfg.ServerKeyPEM == "" {
		if err := config.GenerateServerCert(cfg); err != nil {
			return fmt.Errorf("generate cert: %w", err)
		}
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		logInfo("Generated new server certificate and saved to config.")
	}

	cert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}

	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{cert}

	store := server.NewMemoryStore()
	defer store.Close()

	rl := server.NewRateLimiter(rateLimit, rateBurst)

	if err := config.EnsureLogDir(); err != nil {
		logWarn("could not create log dir", "err", err)
	}
	logFile, err := os.OpenFile(config.LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		logWarn("could not open log file", "err", err)
		logFile = os.Stderr
	} else {
		defer logFile.Close()
	}

	// The serve command always logs to file at the active verbosity level.
	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: toSlogLevel(currentLevel),
	}))

	srv := server.NewServer(store, rl, ttl, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server.RunGC(ctx, store, 60*time.Second)

	printStatus("hermod serve listening on %s", listenAddr)
	return srv.ListenAndServe(ctx, listenAddr, tlsCfg)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
