// Package cli: serve command.
package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/server"
)

// certAutoRenewThreshold is how far before expiry the server replaces its
// certificate automatically. Set to 14 days — long enough to cover holidays
// or extended downtime, short enough that the renewed cert's expiry is not
// pushed out unnecessarily far.
const certAutoRenewThreshold = 14 * 24 * time.Hour

func newServeCmd() *cobra.Command {
	var (
		listen             string
		ttl                int
		rateLimit          float64
		rateBurst          float64
		maxBlobsPerChannel int
		maxCPaceFailures   int
		maxChannelsPerIP   int
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the signaling and NAT helper service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(listen, time.Duration(ttl)*time.Second, rateLimit, rateBurst, maxBlobsPerChannel, maxCPaceFailures, maxChannelsPerIP)
		},
	}

	cmd.Flags().StringVarP(&listen, "listen", "l", envOrDefault("HERMOD_LISTEN", ":4376"), "Bind address (host:port)")
	cmd.Flags().IntVarP(&ttl, "ttl", "T", 600, "Channel TTL in seconds")
	cmd.Flags().Float64Var(&rateLimit, "rate-limit", 5, "Token bucket rate (requests/sec per IP prefix)")
	cmd.Flags().Float64Var(&rateBurst, "rate-burst", 15, "Token bucket burst capacity per IP prefix")
	cmd.Flags().IntVar(&maxBlobsPerChannel, "max-blobs-per-channel", server.DefaultMaxBlobsPerChannel, "Hard cap on relayed blobs per signaling channel")
	cmd.Flags().IntVar(&maxCPaceFailures, "max-cpace-failures", server.DefaultMaxCPaceFailures, "Max CPace handshake failures before a channel is invalidated")
	cmd.Flags().IntVar(&maxChannelsPerIP, "max-channels-per-ip", server.DefaultMaxChannelsPerIP, "Max active channels per IP prefix (IPv4 /32, IPv6 /64)")

	return cmd
}

func runServe(listenAddr string, ttl time.Duration, rateLimit, rateBurst float64, maxBlobsPerChannel, maxCPaceFailures, maxChannelsPerIP int) error {
	// Override the listen address to enforce strict IP family when -4/-6 is set.
	// Only override when bind addr has no explicit IP (e.g. ":4376"), which means
	// net.Listen would bind dual-stack. Explicit addresses like "10.0.0.1:4376" are
	// left alone — the user knows what they want.
	if ipv4Only.Load() && listenAddr[0] == ':' {
		listenAddr = "0.0.0.0" + listenAddr
	} else if ipv6Only.Load() && listenAddr[0] == ':' {
		listenAddr = "[::]" + listenAddr
	}

	logDebug("loading configuration")
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
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
		logInfo("Server certificate saved to configuration file")
	} else {
		logDebug("using existing server certificate from config")
	}

	cert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}
	logDebug("TLS configuration loaded")

	// Warn operators as the certificate approaches expiry. Repeated at startup
	// so that periodic restarts surface the warning ample time in advance.
	config.LogCertExpiry(cfg, func(level, msg string, daysLeft int) {
		switch level {
		case "CRITICAL":
			logError(fmt.Sprintf(msg, daysLeft), "days_left", daysLeft)
		case "ERROR":
			logError(fmt.Sprintf(msg, daysLeft), "days_left", daysLeft)
		default:
			logWarn(fmt.Sprintf(msg, daysLeft), "days_left", daysLeft)
		}
	})

	// Auto-renew the certificate if it expires within the renewal threshold
	// or is already expired. This prevents service disruption from expired
	// certificates and ensures the /cert endpoint always serves a valid cert.
	if notAfter, ok := config.CertExpiryInfo(cfg); ok {
		timeUntilExpiry := time.Until(notAfter)
		if timeUntilExpiry <= certAutoRenewThreshold {
			logInfo("Server certificate expires soon — renewing automatically",
				"days_until_expiry", fmt.Sprintf("%.0f", timeUntilExpiry.Hours()/24))
			if err := config.RenewServerCert(cfg); err != nil {
				return fmt.Errorf("renew certificate: %w", err)
			}
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("save renewed certificate: %w", err)
			}
			// Reload the cert (the key is unchanged, so the SPKI fingerprint
			// stays the same — clients do not need to re-pin).
			cert, err = config.LoadServerTLSCert(cfg)
			if err != nil {
				return fmt.Errorf("load renewed certificate: %w", err)
			}
			logInfo("Server certificate renewed (public key unchanged)")
		}
	}

	// Extract DER bytes for the /cert endpoint.
	var certDER []byte
	if len(cert.Certificate) > 0 {
		certDER = cert.Certificate[0]
	}

	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{cert}
	logDebug("TLS config built",
		"prefer_curves", cfg.TLS.PreferCurves,
		"cipher_suites", cfg.TLS.CipherSuites,
	)

	store := server.NewMemoryStore(maxChannelsPerIP)
	defer store.Close()
	logDebug("in-memory signaling store initialised")

	certRL := server.NewRateLimiter(rateLimit, rateBurst)
	wsRL := server.NewRateLimiter(rateLimit, rateBurst)
	joinRL := server.NewRateLimiter(rateLimit, rateBurst)
	logDebug("rate limiters configured", "rate", rateLimit, "burst", rateBurst)

	// The server uses the global slog logger, which is already wired to stderr
	// at the active verbosity level by applyVerbosity.
	srv := server.NewServer(store, certRL, wsRL, joinRL, ttl, maxBlobsPerChannel, maxCPaceFailures, certDER, nil)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server.RunGC(ctx, store, 60*time.Second)
	logDebug("channel GC started", "interval", "60s")

	logInfo("Server starting", "addr", listenAddr, "channel_ttl", ttl,
		"rate_limit", rateLimit, "rate_burst", rateBurst,
		"max_blobs_per_channel", maxBlobsPerChannel, "max_cpace_failures", maxCPaceFailures)

	fingerprint := config.PubKeyFingerprint(certDER)
	printStatus("Listening on %s", listenAddr)
	printStatus("Server public key fingerprint: %s", fingerprint)

	err = srv.ListenAndServe(ctx, listenAddr, tlsCfg)
	if err != nil {
		logError("Server stopped with error", "err", err)
	} else {
		logInfo("Server stopped")
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
