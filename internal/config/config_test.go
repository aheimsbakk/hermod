package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hermod/hermod/internal/config"
)

func TestDefault(t *testing.T) {
	cfg := config.Default()
	if cfg.ServerURL == "" {
		t.Fatal("default server URL is empty")
	}
	if cfg.Listen == "" {
		t.Fatal("default listen address is empty")
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

func TestCertFingerprint(t *testing.T) {
	cfg := config.Default()
	if err := config.GenerateServerCert(cfg); err != nil {
		t.Fatal(err)
	}
	tlsCert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fp := config.CertFingerprint(tlsCert.Certificate[0])
	if len(fp) != 64 {
		t.Fatalf("expected 64-char hex fingerprint, got %q", fp)
	}
	// Fingerprint should be deterministic
	fp2 := config.CertFingerprint(tlsCert.Certificate[0])
	if fp != fp2 {
		t.Fatal("fingerprint not deterministic")
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
