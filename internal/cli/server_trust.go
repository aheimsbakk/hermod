// Package cli: server trust enforcement for tx and rx commands.
package cli

import (
	"fmt"

	"github.com/hermod/hermod/internal/config"
)

// requireTrustedServer returns the pinned SPKI fingerprint for serverURL.
// It returns an error if the server has no entry in cfg.TrustedServers, directing
// the user to run 'hermod trust <server>' before using tx or rx.
func requireTrustedServer(cfg *config.Config, serverURL string) (string, error) {
	fp, ok := cfg.TrustedServers[serverURL]
	if !ok || fp == "" {
		return "", fmt.Errorf(
			"server %q is not trusted: run 'hermod trust %s' first to pin its certificate",
			serverURL, serverURL,
		)
	}
	return fp, nil
}
