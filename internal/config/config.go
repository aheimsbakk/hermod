// Package config manages persistent YAML configuration for hermod.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// TLSConfig holds curve and cipher preferences.
type TLSConfig struct {
	PreferCurves []string `yaml:"prefer_curves"`
	CipherSuites []string `yaml:"cipher_suites"`
}

// Config is the top-level application configuration.
type Config struct {
	ServerURL      string            `yaml:"server_url"`
	TLS            TLSConfig         `yaml:"tls_configuration"`
	ServerCertPEM  string            `yaml:"server_cert_pem,omitempty"`
	ServerKeyPEM   string            `yaml:"server_key_pem,omitempty"`
	TrustedServers map[string]string `yaml:"trusted_servers,omitempty"`
}

// Default returns a Config populated with application defaults.
func Default() *Config {
	return &Config{
		ServerURL: "wss://localhost:4376",
		TLS: TLSConfig{
			PreferCurves: []string{"X25519MLKEM768"},
			CipherSuites: []string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"},
		},
		TrustedServers: map[string]string{},
	}
}

// Dir returns the platform-specific config directory.
func Dir() string {
	if runtime.GOOS == "windows" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return filepath.Join(os.TempDir(), "Hermod")
		}
		return filepath.Join(dir, "Hermod")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		// Fall back to /tmp/hermod-<uid>. This avoids writing the
		// server private key to an uncontrolled working directory like ".".
		return fmt.Sprintf("/tmp/hermod-%d", os.Getuid())
	}
	return filepath.Join(home, ".config", "hermod")
}

// Path returns the full path to config.yaml.
func Path() string {
	return filepath.Join(Dir(), "config.yaml")
}

// Load reads config from disk, merging with defaults.
func Load() (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(Path())
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// Save writes cfg to disk, creating directories as needed.
func Save(cfg *Config) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(Path(), data, 0o600)
}

// NormalizeServerURL canonicalizes a server URL to scheme://host:port form.
// It drops the path, query, and fragment components, lowercases the host,
// defaults the scheme to "wss" and the port to 4376.
// Returns an error if the input is empty or cannot be parsed as a URL.
// Examples:
//
//	wss://Relay:4376/ws  →  wss://relay:4376
//	relay                →  wss://relay:4376
//	ws://relay:9090      →  ws://relay:9090
func NormalizeServerURL(serverURL string) (string, error) {
	if serverURL == "" {
		return "", fmt.Errorf("server URL is empty")
	}
	if !strings.HasPrefix(serverURL, "wss://") && !strings.HasPrefix(serverURL, "ws://") {
		serverURL = "wss://" + serverURL
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("server URL %q has no host component", serverURL)
	}
	port := u.Port()
	if port == "" {
		port = "4376"
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port), nil
}

// PinServer stores the server's SPKI fingerprint in cfg.
// Use PubKeyFingerprint to compute this value.
// The serverURL is normalized to scheme://host:port before storing (see NormalizeServerURL).
func PinServer(cfg *Config, serverURL, fingerprint string) {
	normalized, err := NormalizeServerURL(serverURL)
	if err != nil {
		return // silent skip; invalid URLs produce no entry
	}
	if cfg.TrustedServers == nil {
		cfg.TrustedServers = map[string]string{}
	}
	cfg.TrustedServers[normalized] = fingerprint
}

// SetDefaultServer sets cfg.ServerURL to serverURL.
// The URL is normalized to scheme://host:port before storing (see NormalizeServerURL).
// Call Save after to persist the change.
func SetDefaultServer(cfg *Config, serverURL string) {
	normalized, err := NormalizeServerURL(serverURL)
	if err != nil {
		return // silent skip; invalid URLs leave the current value
	}
	cfg.ServerURL = normalized
}
