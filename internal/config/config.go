// Package config manages persistent YAML configuration for hermod.
package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"

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
	Listen         string            `yaml:"listen"`
	TLS            TLSConfig         `yaml:"tls_configuration"`
	ServerCertPEM  string            `yaml:"server_cert_pem,omitempty"`
	ServerKeyPEM   string            `yaml:"server_key_pem,omitempty"`
	TrustedServers map[string]string `yaml:"trusted_servers,omitempty"`
}

// Default returns a Config populated with application defaults.
func Default() *Config {
	return &Config{
		ServerURL: "wss://localhost:4376",
		Listen:    ":0",
		TLS: TLSConfig{
			PreferCurves: []string{"X25519MLKEM768", "X25519", "CurveP256"},
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
		// Fall back to /tmp/hermod-<uid> (M-06). This avoids writing the
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

// TLSCurveIDs maps curve name strings to tls.CurveID values.
func TLSCurveIDs(names []string) []tls.CurveID {
	table := map[string]tls.CurveID{
		"X25519MLKEM768": tls.X25519MLKEM768,
		"X25519":         tls.X25519,
		"CurveP256":      tls.CurveP256,
		"CurveP384":      tls.CurveP384,
		"CurveP521":      tls.CurveP521,
	}
	out := make([]tls.CurveID, 0, len(names))
	for _, n := range names {
		if id, ok := table[n]; ok {
			out = append(out, id)
		}
	}
	return out
}

// TLSCipherSuiteIDs maps cipher suite name strings to uint16 IDs.
func TLSCipherSuiteIDs(names []string) []uint16 {
	table := map[string]uint16{
		"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
	}
	out := make([]uint16, 0, len(names))
	for _, n := range names {
		if id, ok := table[n]; ok {
			out = append(out, id)
		}
	}
	return out
}

// BuildTLSConfig constructs a *tls.Config from the stored preferences.
func BuildTLSConfig(cfg *Config) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: TLSCurveIDs(cfg.TLS.PreferCurves),
		CipherSuites:     TLSCipherSuiteIDs(cfg.TLS.CipherSuites),
	}
}

// GenerateServerCert generates a self-signed X.509 cert+key and stores PEM
// strings in cfg. Uses ECDSA P-256 for fast generation and smaller signatures (L-02).
func GenerateServerCert(cfg *Config) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "hermod-server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}
	cfg.ServerCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	cfg.ServerKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return nil
}

// LoadServerTLSCert parses the PEM cert+key from cfg into a tls.Certificate.
func LoadServerTLSCert(cfg *Config) (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(cfg.ServerCertPEM), []byte(cfg.ServerKeyPEM))
}

// CertFingerprint computes the SHA-256 fingerprint of a DER-encoded certificate
// and returns it as a lowercase hex string.
func CertFingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

// PinServer stores the server's certificate fingerprint in cfg.
func PinServer(cfg *Config, serverURL, fingerprint string) {
	if cfg.TrustedServers == nil {
		cfg.TrustedServers = map[string]string{}
	}
	cfg.TrustedServers[serverURL] = fingerprint
}

// SetDefaultServer sets cfg.ServerURL to serverURL.
// Call Save after to persist the change.
func SetDefaultServer(cfg *Config, serverURL string) {
	cfg.ServerURL = serverURL
}

// CertExpiryInfo returns the expiry time of the server certificate stored in
// cfg, and whether it could be parsed. Returns zero time and false if the cert
// is missing or unparseable.
func CertExpiryInfo(cfg *Config) (notAfter time.Time, ok bool) {
	if cfg.ServerCertPEM == "" {
		return time.Time{}, false
	}
	block, _ := pem.Decode([]byte(cfg.ServerCertPEM))
	if block == nil {
		return time.Time{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return cert.NotAfter, true
}

// certExpiryThresholds defines log-level thresholds for cert expiry warnings.
// Each entry: days remaining → (level, message).
// Checked in order; the first match applies.
var certExpiryThresholds = []struct {
	days  int
	level string
	msg   string
}{
	{7, "CRITICAL", "Server certificate expires in %d day(s) — renew immediately to avoid outages"},
	{30, "ERROR", "Server certificate expires in %d day(s) — schedule renewal soon"},
	{90, "WARN", "Server certificate expires in %d day(s) — consider renewing"},
}

// LogCertExpiry logs a warning (or critical) message if the server certificate
// is approaching expiry. It does nothing if the cert cannot be parsed or is
// not configured. Callers should invoke this at server startup and periodically.
//
// Log levels used:
//   - ≤ 7 days  → CRITICAL (slog.LevelError, prefix "CRITICAL")
//   - ≤ 30 days → ERROR    (slog.LevelError)
//   - ≤ 90 days → WARN     (slog.LevelWarn)
func LogCertExpiry(cfg *Config, logFn func(level, msg string, daysLeft int)) {
	notAfter, ok := CertExpiryInfo(cfg)
	if !ok {
		return
	}
	daysLeft := int(time.Until(notAfter).Hours() / 24)
	for _, t := range certExpiryThresholds {
		if daysLeft <= t.days {
			logFn(t.level, t.msg, daysLeft)
			return
		}
	}
}
