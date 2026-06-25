// Package cli: trust command — fetch and pin a server's TLS certificate.
package cli

import (
	"context"
	"fmt"
	"net/url"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/network"
)

func newTrustCmd() *cobra.Command {
	var knownFingerprint string

	cmd := &cobra.Command{
		Use:   "trust <server>",
		Short: "Fetch and pin the public certificate of a signaling server",
		Long: `Connects to the signaling server, fetches its TLS certificate,
and pins the SHA-256 Subject Public Key Info (SPKI) fingerprint in the local
config. SPKI pinning is used instead of certificate DER pinning so that the
pin remains valid across certificate renewals that reuse the same key pair.

Security note: the initial connection is made without certificate verification
(TOFU — trust on first use). Run this command over a trusted network (VPN,
physical LAN, or a channel where the fingerprint can be verified out-of-band).

Use --fingerprint to supply a pre-known fingerprint. The server's TLS
certificate is verified against this value during the TLS handshake,
preventing TOFU attacks when the fingerprint is already known.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrust(args[0], knownFingerprint)
		},
	}

	cmd.Flags().StringVar(&knownFingerprint, "fingerprint", "",
		"Expected SHA-256 fingerprint (hex) — if set, the fetched cert is verified against this value before pinning")

	return cmd
}

func runTrust(serverArg, knownFingerprint string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Normalize: if no scheme, prepend wss://
	connectURL := serverArg
	if len(connectURL) < 4 || connectURL[:4] != "wss:" && connectURL[:3] != "ws:" {
		connectURL = "wss://" + connectURL
	}

	// Reject plaintext WebSocket
	u, err := url.Parse(connectURL)
	if err != nil {
		return fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme == "ws" {
		return fmt.Errorf("plaintext WebSocket (ws://) is not allowed by default; use wss://")
	}

	// Default to port 4376 when no port is specified
	if u.Port() == "" {
		connectURL = "wss://" + u.Host + ":4376" + u.Path
	}

	// Normalize for pinning key (scheme://host:port, drop path)
	canonical, err := config.NormalizeServerURL(serverArg)
	if err != nil {
		return fmt.Errorf("parse server URL: %w", err)
	}

	printStatus("Connecting to %s to fetch certificate...", connectURL)

	sigFamily := network.IPFamilyAny
	switch {
	case ipv4Only.Load():
		sigFamily = network.IPFamilyV4
	case ipv6Only.Load():
		sigFamily = network.IPFamilyV6
	}
	fp, err := network.FetchServerFingerprint(ctx, connectURL, knownFingerprint, sigFamily)
	if err != nil {
		return fmt.Errorf("fetch fingerprint: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	config.PinServer(cfg, canonical, fp)
	config.SetDefaultServer(cfg, canonical)

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	printStatus("Pinned %s\n  fingerprint: %s\n  set as default server", canonical, fp)
	return nil
}
