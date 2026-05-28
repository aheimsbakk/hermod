// Package cli: trust command — fetch and pin a server's TLS certificate.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/network"
)

func newTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust <server>",
		Short: "Fetch and pin the public certificate of a signaling server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrust(args[0])
		},
	}
	return cmd
}

func runTrust(serverArg string) error {
	// Normalize: if no scheme, prepend wss://
	serverURL := serverArg
	if len(serverURL) < 4 || serverURL[:4] != "wss:" && serverURL[:3] != "ws:" {
		serverURL = "wss://" + serverURL
	}

	printStatus("Connecting to %s to fetch certificate...", serverURL)

	fp, err := network.FetchServerFingerprint(serverURL)
	if err != nil {
		return fmt.Errorf("fetch fingerprint: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	config.PinServer(cfg, serverURL, fp)

	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	printStatus("Pinned %s\n  fingerprint: %s", serverURL, fp)
	return nil
}
