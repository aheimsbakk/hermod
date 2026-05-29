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
	logDebug("loading config")
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logDebug("config loaded", "path", config.Path())

	// Generate server cert on first run
	if cfg.ServerCertPEM == "" || cfg.ServerKeyPEM == "" {
		logInfo("No server certificate found — generating a new self-signed certificate")
		if err := config.GenerateServerCert(cfg); err != nil {
			return fmt.Errorf("generate cert: %w", err)
		}
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		logInfo("Server certificate saved to config")
	} else {
		logDebug("using existing server certificate from config")
	}

	cert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}
	logDebug("TLS certificate loaded")

	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{cert}
	logDebug("TLS config built",
		"prefer_curves", cfg.TLS.PreferCurves,
		"cipher_suites", cfg.TLS.CipherSuites,
	)

	store := server.NewMemoryStore()
	defer store.Close()
	logDebug("in-memory signaling store initialised")

	rl := server.NewRateLimiter(rateLimit, rateBurst)
	logDebug("rate limiter configured", "rate", rateLimit, "burst", rateBurst)

	if err := config.EnsureLogDir(); err != nil {
		logWarn("could not create log directory — server events will not be persisted to disk", "err", err)
	}
	logFile, err := os.OpenFile(config.LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		logWarn("could not open log file — server events will go to stderr only", "path", config.LogPath(), "err", err)
		logFile = os.Stderr
	} else {
		defer logFile.Close()
		logDebug("server log file opened", "path", config.LogPath())
	}

	// The serve command always logs to file at the active verbosity level.
	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: toSlogLevel(currentLevel),
	}))

	srv := server.NewServer(store, rl, ttl, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server.RunGC(ctx, store, 60*time.Second)
	logDebug("channel GC started", "interval", "60s")

	logInfo("Server starting", "addr", listenAddr, "channel_ttl", ttl, "rate_limit", rateLimit, "rate_burst", rateBurst)
	printStatus("hermod serve listening on %s", listenAddr)
	err = srv.ListenAndServe(ctx, listenAddr, tlsCfg)
	if err != nil {
		logError("Server stopped with error", "err", err)
	} else {
		logInfo("Server stopped cleanly")
	}
	return err
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// configServerURL returns the default server URL using this priority order:
//  1. HERMOD_SERVER environment variable
//  2. server_url stored in the config file
//  3. hardcoded fallback ("wss://localhost:4376")
func configServerURL() string {
	if v := os.Getenv("HERMOD_SERVER"); v != "" {
		return v
	}
	cfg, err := config.Load()
	if err == nil && cfg.ServerURL != "" {
		return cfg.ServerURL
	}
	return "wss://localhost:4376"
}
