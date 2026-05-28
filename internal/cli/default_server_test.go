// Package cli: tests verifying that tx and rx read and write the default
// server URL from the config file.
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hermod/hermod/internal/config"
)

// setupTempHome redirects the config location to a fresh temporary directory
// and returns a cleanup function. It also clears HERMOD_SERVER so the env var
// does not override the config-file value.
func setupTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir) // Windows
	t.Setenv("HERMOD_SERVER", "")
	return dir
}

// writeConfig saves cfg to the temp config path and fatals on error.
func writeConfig(t *testing.T, cfg *config.Config) {
	t.Helper()
	if err := config.Save(cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// loadConfig loads config from the temp config path and fatals on error.
func loadConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	return cfg
}

// TestTxUsesConfigDefaultServer verifies that when tx is invoked without -s,
// it connects to the server URL stored in the config file (not the hardcoded
// fallback). The connection will fail because no real server is running; we
// assert the error message contains the expected URL.
func TestTxUsesConfigDefaultServer(t *testing.T) {
	setupTempHome(t)

	cfg := config.Default()
	cfg.ServerURL = "wss://config-default.example.com:4376"
	writeConfig(t, cfg)

	// Write a throwaway temp file to send.
	f, err := os.CreateTemp(t.TempDir(), "tx-input-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	_, _ = f.WriteString("hello")
	f.Close()

	err = ExecuteArgs([]string{"hermod", "tx", f.Name()})
	if err == nil {
		t.Fatal("expected an error (no server running), got nil")
	}
	if !strings.Contains(err.Error(), "config-default.example.com") {
		t.Errorf("expected error to mention config server URL, got: %v", err)
	}
}

// TestRxUsesConfigDefaultServer verifies that when rx is invoked without -s,
// it connects to the server URL stored in the config file.
func TestRxUsesConfigDefaultServer(t *testing.T) {
	setupTempHome(t)

	cfg := config.Default()
	cfg.ServerURL = "wss://config-default.example.com:4376"
	writeConfig(t, cfg)

	err := ExecuteArgs([]string{"hermod", "rx", "3-apple-banana-cherry"})
	if err == nil {
		t.Fatal("expected an error (no server running), got nil")
	}
	if !strings.Contains(err.Error(), "config-default.example.com") {
		t.Errorf("expected error to mention config server URL, got: %v", err)
	}
}

// TestTxWithExplicitServerSavesDefault verifies that passing -s on tx updates
// server_url in the config file for future invocations.
func TestTxWithExplicitServerSavesDefault(t *testing.T) {
	setupTempHome(t)

	// Start with default config (localhost).
	writeConfig(t, config.Default())

	f, err := os.CreateTemp(t.TempDir(), "tx-input-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	_, _ = f.WriteString("hello")
	f.Close()

	newServer := "wss://new-default.example.com:4376"
	// The command will fail (no server) — we only care that the config was saved.
	_ = ExecuteArgs([]string{"hermod", "tx", f.Name(), "-s", newServer})

	saved := loadConfig(t)
	if saved.ServerURL != newServer {
		t.Errorf("expected saved server URL %q, got %q", newServer, saved.ServerURL)
	}
}

// TestRxWithExplicitServerSavesDefault verifies that passing -s on rx updates
// server_url in the config file for future invocations.
func TestRxWithExplicitServerSavesDefault(t *testing.T) {
	setupTempHome(t)

	writeConfig(t, config.Default())

	newServer := "wss://new-default.example.com:4376"
	// The command will fail (no server) — we only care that the config was saved.
	_ = ExecuteArgs([]string{"hermod", "rx", "3-apple-banana-cherry", "-s", newServer})

	saved := loadConfig(t)
	if saved.ServerURL != newServer {
		t.Errorf("expected saved server URL %q, got %q", newServer, saved.ServerURL)
	}
}

// TestTxDoesNotSaveDefaultWhenServerUnchanged verifies that when tx is called
// without -s and the server has not changed, the config file is not rewritten
// with a different value (i.e. saveServer=false path).
func TestTxDoesNotSaveDefaultWhenServerUnchanged(t *testing.T) {
	setupTempHome(t)

	cfg := config.Default()
	cfg.ServerURL = "wss://stable.example.com:4376"
	writeConfig(t, cfg)

	// Record the file mod time before the command.
	cfgPath := filepath.Join(config.Dir(), "config.yaml")
	before, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}

	f, ferr := os.CreateTemp(t.TempDir(), "tx-input-*.txt")
	if ferr != nil {
		t.Fatalf("create temp file: %v", ferr)
	}
	_, _ = f.WriteString("hello")
	f.Close()

	// Run without -s — saveServer=false, config should not be touched.
	_ = ExecuteArgs([]string{"hermod", "tx", f.Name()})

	after, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat config after: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("config file was rewritten even though -s was not passed")
	}
}

// TestNextInvocationUsesUpdatedDefault verifies the full round-trip: after tx
// saves a new default, a subsequent tx call (without -s) picks up that server.
func TestNextInvocationUsesUpdatedDefault(t *testing.T) {
	setupTempHome(t)
	writeConfig(t, config.Default())

	f, err := os.CreateTemp(t.TempDir(), "tx-input-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	_, _ = f.WriteString("hello")
	f.Close()

	newServer := "wss://updated.example.com:4376"

	// First call: set -s explicitly → saves new default.
	_ = ExecuteArgs([]string{"hermod", "tx", f.Name(), "-s", newServer})

	// Verify config was updated.
	if saved := loadConfig(t); saved.ServerURL != newServer {
		t.Fatalf("first call did not save new server; got %q", saved.ServerURL)
	}

	// Second call: no -s → should attempt the newly saved server.
	err = ExecuteArgs([]string{"hermod", "tx", f.Name()})
	if err == nil {
		t.Fatal("expected error (no server running)")
	}
	if !strings.Contains(err.Error(), "updated.example.com") {
		t.Errorf("second call did not use updated default server; error: %v", err)
	}
}
