package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hermod/hermod/internal/config"
)

func TestDefault(t *testing.T) {
	cfg := config.Default()
	if cfg.ServerURL == "" {
		t.Fatal("default server URL is empty")
	}
	if len(cfg.TLS.PreferCurves) == 0 {
		t.Fatal("default TLS curves are empty")
	}
	if len(cfg.TLS.CipherSuites) == 0 {
		t.Fatal("default TLS cipher suites are empty")
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	// Point config to temp dir via env var
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)

	cfg := config.Default()
	cfg.ServerURL = "wss://test.example.com:9999"

	if err := config.Save(cfg); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.ServerURL != "wss://test.example.com:9999" {
		t.Fatalf("expected %q, got %q", "wss://test.example.com:9999", loaded.ServerURL)
	}
}

func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// No file created — should return defaults
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load missing: %v", err)
	}
	if cfg.ServerURL == "" {
		t.Fatal("expected default server URL")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	cfgDir := filepath.Join(dir, ".config", "hermod")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("server_url: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestTLSCurveIDs(t *testing.T) {
	ids := config.TLSCurveIDs([]string{"X25519", "CurveP256", "unknown"})
	if len(ids) != 2 {
		t.Fatalf("expected 2 known curves, got %d", len(ids))
	}
}

func TestTLSCurveIDsAllKnown(t *testing.T) {
	ids := config.TLSCurveIDs([]string{"X25519MLKEM768", "X25519", "CurveP256", "CurveP384", "CurveP521"})
	if len(ids) != 5 {
		t.Fatalf("expected 5 curves, got %d", len(ids))
	}
}

func TestTLSCipherSuiteIDs(t *testing.T) {
	ids := config.TLSCipherSuiteIDs([]string{"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "nope"})
	if len(ids) != 2 {
		t.Fatalf("expected 2 known suites, got %d", len(ids))
	}
}

func TestBuildTLSConfig(t *testing.T) {
	cfg := config.Default()
	tlsCfg := config.BuildTLSConfig(cfg)
	if tlsCfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
}

func TestGenerateServerCert(t *testing.T) {
	cfg := config.Default()
	if err := config.GenerateServerCert(cfg); err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	if cfg.ServerCertPEM == "" {
		t.Fatal("server cert PEM is empty")
	}
	if cfg.ServerKeyPEM == "" {
		t.Fatal("server key PEM is empty")
	}

	if _, err := config.LoadServerTLSCert(cfg); err != nil {
		t.Fatalf("load cert: %v", err)
	}
}

func TestPubKeyFingerprint(t *testing.T) {
	cfg := config.Default()
	if err := config.GenerateServerCert(cfg); err != nil {
		t.Fatal(err)
	}
	tlsCert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pkfp := config.PubKeyFingerprint(tlsCert.Certificate[0])
	if len(pkfp) != 64 {
		t.Fatalf("expected 64-char hex SPKI fingerprint, got %q", pkfp)
	}
	// Fingerprint should be deterministic
	pkfp2 := config.PubKeyFingerprint(tlsCert.Certificate[0])
	if pkfp != pkfp2 {
		t.Fatal("SPKI fingerprint not deterministic")
	}
}

func TestPubKeyFingerprint_Invalid(t *testing.T) {
	fp := config.PubKeyFingerprint([]byte("invalid"))
	if fp != "" {
		t.Fatalf("expected empty string for invalid DER, got %q", fp)
	}
}

func TestPinServer(t *testing.T) {
	cfg := config.Default()
	config.PinServer(cfg, "wss://example.com:4376", "aabbcc")
	if cfg.TrustedServers["wss://example.com:4376"] != "aabbcc" {
		t.Fatal("pin not stored")
	}
	// Pin another server
	config.PinServer(cfg, "wss://other.com:4376", "ddeeff")
	if len(cfg.TrustedServers) != 2 {
		t.Fatal("expected 2 trusted servers")
	}
}

func TestPinServerNilMap(t *testing.T) {
	cfg := config.Default()
	cfg.TrustedServers = nil
	config.PinServer(cfg, "wss://x.com:4376", "aabb")
	if cfg.TrustedServers["wss://x.com:4376"] != "aabb" {
		t.Fatal("pin not stored after nil map init")
	}
}

func TestSetDefaultServer(t *testing.T) {
	cfg := config.Default()
	config.SetDefaultServer(cfg, "wss://new.example.com:4376")
	if cfg.ServerURL != "wss://new.example.com:4376" {
		t.Fatalf("expected %q, got %q", "wss://new.example.com:4376", cfg.ServerURL)
	}
}

func TestTrustSetsDefaultServer(t *testing.T) {
	cfg := config.Default()
	config.PinServer(cfg, "wss://example.com:4376", "aabb")
	config.SetDefaultServer(cfg, "wss://example.com:4376")
	if cfg.ServerURL != "wss://example.com:4376" {
		t.Fatalf("expected server URL to be set, got %q", cfg.ServerURL)
	}
}

// --- NormalizeServerURL ---

func TestNormalizeServerURL_StripsPath(t *testing.T) {
	got, err := config.NormalizeServerURL("wss://relay:4376/ws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://relay:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_StripsTrailingSlash(t *testing.T) {
	got, err := config.NormalizeServerURL("wss://relay:4376/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://relay:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_LowercasesHost(t *testing.T) {
	got, err := config.NormalizeServerURL("wss://RELAY:4376")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://relay:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_DefaultsPort(t *testing.T) {
	got, err := config.NormalizeServerURL("wss://relay")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://relay:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_DefaultsSchemeAndPort(t *testing.T) {
	got, err := config.NormalizeServerURL("relay")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://relay:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_StripsQueryString(t *testing.T) {
	got, err := config.NormalizeServerURL("wss://relay:4376?token=abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://relay:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_KeepsNonDefaultPort(t *testing.T) {
	got, err := config.NormalizeServerURL("wss://relay:9090")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://relay:9090"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_KeepsWSScheme(t *testing.T) {
	got, err := config.NormalizeServerURL("ws://relay:4376")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "ws://relay:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_IPv6Preserved(t *testing.T) {
	got, err := config.NormalizeServerURL("wss://[::1]:4376")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://[::1]:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_IPv4Preserved(t *testing.T) {
	got, err := config.NormalizeServerURL("wss://192.168.1.1:4376")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "wss://192.168.1.1:4376"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNormalizeServerURL_EmptyReturnsError(t *testing.T) {
	_, err := config.NormalizeServerURL("")
	if err == nil {
		t.Fatal("expected error for empty URL, got nil")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected 'empty' in error, got: %v", err)
	}
}

func TestNormalizeServerURL_NoHostReturnsError(t *testing.T) {
	_, err := config.NormalizeServerURL("wss:///path")
	if err == nil {
		t.Fatal("expected error for URL with no host, got nil")
	}
	if !strings.Contains(err.Error(), "no host") {
		t.Errorf("expected 'no host' in error, got: %v", err)
	}
}

// --- PinServer normalization ---

func TestPinServer_NormalizesURL(t *testing.T) {
	cfg := config.Default()
	config.PinServer(cfg, "wss://RELAY:4376/ws", "fingerprint")
	if got := cfg.TrustedServers["wss://relay:4376"]; got != "fingerprint" {
		t.Fatalf("expected pinned key 'wss://relay:4376', got %q (map: %v)", got, cfg.TrustedServers)
	}
}

func TestPinServer_RawVariantAccessible(t *testing.T) {
	cfg := config.Default()
	config.PinServer(cfg, "wss://relay:4376/ws", "path-variant")
	config.PinServer(cfg, "wss://relay:4376", "clean-variant")
	// Both variants should map to the same normalized key — the second pin overwrites the first.
	if len(cfg.TrustedServers) != 1 {
		t.Fatalf("expected 1 entry in TrustedServers (both URLs normalize to same), got %d", len(cfg.TrustedServers))
	}
	if cfg.TrustedServers["wss://relay:4376"] != "clean-variant" {
		t.Fatalf("expected 'clean-variant', got %q", cfg.TrustedServers["wss://relay:4376"])
	}
}

// --- SetDefaultServer normalization ---

func TestSetDefaultServer_NormalizesURL(t *testing.T) {
	cfg := config.Default()
	config.SetDefaultServer(cfg, "wss://Relay:4376/ws")
	want := "wss://relay:4376"
	if cfg.ServerURL != want {
		t.Fatalf("expected %q, got %q", want, cfg.ServerURL)
	}
}

func TestSetDefaultServer_InvalidURL(t *testing.T) {
	cfg := config.Default()
	cfg.ServerURL = "wss://existing:4376"
	config.SetDefaultServer(cfg, "://bad")
	if cfg.ServerURL != "wss://existing:4376" {
		t.Fatalf("expected existing server URL to be preserved, got %q", cfg.ServerURL)
	}
}
