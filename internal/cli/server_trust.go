// Package cli: server trust enforcement for tx and rx commands.
package cli

import (
	"fmt"

	"github.com/hermod/hermod/internal/config"
)

// requireTrustedServer returns the pinned SPKI fingerprint for serverURL.
// It returns an error if the server has no entry in cfg.TrustedServers, directing
// the user to run 'hermod trust <server>' before using tx or rx.
// The serverURL is normalized to scheme://host:port before lookup (see config.NormalizeServerURL),
// so variant spellings (e.g. with/without trailing slash, with/without port) all resolve.
func requireTrustedServer(cfg *config.Config, serverURL string) (string, error) {
	normalized, err := config.NormalizeServerURL(serverURL)
	if err != nil {
		return "", fmt.Errorf(
			"server URL %q is not valid: %v",
			serverURL, err,
		)
	}
	fp, ok := cfg.TrustedServers[normalized]
	if !ok || fp == "" {
		return "", fmt.Errorf(
			"server %q is not trusted: run 'hermod trust %s' first to pin its certificate",
			serverURL, normalized,
		)
	}
	return fp, nil
}
