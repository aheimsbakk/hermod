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
and pins the SHA-256 fingerprint in the local config.

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
	serverURL := serverArg
	if len(serverURL) < 4 || serverURL[:4] != "wss:" && serverURL[:3] != "ws:" {
		serverURL = "wss://" + serverURL
	}

	// Default to port 4376 when no port is specified
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme == "ws" {
		return fmt.Errorf("plaintext WebSocket (ws://) is not allowed by default; use wss://")
	}
	if u.Port() == "" {
		serverURL = "wss://" + u.Host + ":4376" + u.Path
	}

	printStatus("Connecting to %s to fetch certificate...", serverURL)

	sigFamily := network.IPFamilyAny
	switch {
	case ipv4Only:
		sigFamily = network.IPFamilyV4
	case ipv6Only:
		sigFamily = network.IPFamilyV6
	}
	fp, err := network.FetchServerFingerprint(ctx, serverURL, knownFingerprint, sigFamily)
	if err != nil {
		return fmt.Errorf("fetch fingerprint: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	config.PinServer(cfg, serverURL, fp)
	config.SetDefaultServer(cfg, serverURL)

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	printStatus("Pinned %s\n  fingerprint: %s\n  set as default server", serverURL, fp)
	return nil
}
