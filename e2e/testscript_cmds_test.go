// Package e2e: custom testscript commands for full-transfer integration tests.
package e2e_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/hermod/hermod/internal/cli"
	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/server"
)

// txState holds goroutine state for a background tx run.
type txState struct {
	errCh chan error
}

// txStateMap stores per-workdir txState values shared between
// tx-background and tx-wait custom commands.
var txStateMap sync.Map

// scriptCmds returns the custom command map for testscript.Run.
func scriptCmds() map[string]func(*testscript.TestScript, bool, []string) {
	return map[string]func(*testscript.TestScript, bool, []string){
		"start-server":  cmdStartServer,
		"tx-background": cmdTxBackground,
		"tx-wait":       cmdTxWait,
	}
}

// cmdStartServer starts an in-process signaling server on a random loopback
// port, writes a trusted-server config to the testscript HOME, and sets
// $HERMOD_SERVER in the testscript environment.
//
// Usage in .txtar:
//
//	start-server
func cmdStartServer(ts *testscript.TestScript, neg bool, _ []string) {
	cfg := config.Default()
	if err := config.GenerateServerCert(cfg); err != nil {
		ts.Fatalf("start-server: generate cert: %v", err)
	}
	tlsCert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		ts.Fatalf("start-server: load TLS cert: %v", err)
	}
	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	store := server.NewMemoryStore()
	rl := server.NewRateLimiter(100, 1000)
	srv := server.NewServer(
		store, rl, 60*time.Second,
		server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures,
		nil, slog.Default(),
	)

	// Pick a free port before starting.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ts.Fatalf("start-server: listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	ts.Defer(cancel)

	go srv.ListenAndServe(ctx, addr, tlsCfg) //nolint:errcheck

	// Wait until the TCP port is accepting connections (up to 3 s).
	deadline := time.Now().Add(3 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if c, dialErr := net.Dial("tcp", addr); dialErr == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		cancel()
		ts.Fatalf("start-server: server did not start within 3 s")
	}

	serverURL := "wss://" + addr
	fingerprint := config.CertFingerprint(tlsCert.Certificate[0])

	// Write a trusted-server config so that cli.ExecuteArgs calls (both
	// in-process via tx-background and subprocess via exec) accept this server.
	// We redirect HOME to the testscript's home dir so the config lands there.
	homeDir := ts.Getenv("HOME")
	if homeDir == "" {
		homeDir = ts.MkAbs("home")
	}
	trustedCfg := config.Default()
	trustedCfg.ServerURL = serverURL
	config.PinServer(trustedCfg, serverURL, fingerprint)
	// Temporarily update the OS HOME so in-process config.Load() finds the file.
	origHome := os.Getenv("HOME")
	if err2 := os.Setenv("HOME", homeDir); err2 != nil {
		ts.Fatalf("start-server: set HOME: %v", err2)
	}
	ts.Defer(func() { os.Setenv("HOME", origHome) }) //nolint:errcheck
	if err2 := config.Save(trustedCfg); err2 != nil {
		ts.Fatalf("start-server: save trusted config: %v", err2)
	}

	ts.Setenv("HERMOD_SERVER", serverURL)
	ts.Logf("start-server: listening at %s (fingerprint: %s)", serverURL, fingerprint)
}

// cmdTxBackground runs hermod tx in a background goroutine with stdout
// captured. The command blocks until "Transfer code: XXXX" is seen on
// stdout, then sets $HERMOD_CODE and returns. The tx goroutine continues
// running; call tx-wait to collect it.
//
// Usage in .txtar:
//
//	tx-background <input-path-or-text>
func cmdTxBackground(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) == 0 {
		ts.Fatalf("tx-background: expected at least one argument (file path or text)")
	}
	serverURL := ts.Getenv("HERMOD_SERVER")
	if serverURL == "" {
		ts.Fatalf("tx-background: $HERMOD_SERVER is not set; run start-server first")
	}

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		ts.Fatalf("tx-background: create pipe: %v", err)
	}

	codeCh := make(chan string, 1)

	// Scan tx stdout and extract the transfer code line.
	go func() {
		defer stdoutR.Close()
		scanner := bufio.NewScanner(stdoutR)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "Transfer code:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					codeCh <- strings.TrimSpace(parts[1])
				}
				return
			}
		}
		close(codeCh)
	}()

	errCh := make(chan error, 1)
	txArgs := append([]string{"hermod", "tx", "--server", serverURL, "--words", "3"}, args...)

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	os.Stdout = stdoutW
	os.Stderr = stdoutW
	go func() {
		txErr := cli.ExecuteArgs(txArgs)
		stdoutW.Close()
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		errCh <- txErr
	}()

	select {
	case code, ok := <-codeCh:
		if !ok || code == "" {
			ts.Fatalf("tx-background: transfer code not found in tx output (stdout/stderr)")
		}
		ts.Setenv("HERMOD_CODE", code)
	case <-time.After(15 * time.Second):
		ts.Fatalf("tx-background: timed out waiting for transfer code")
	}

	key := ts.MkAbs(".")
	txStateMap.Store(key, &txState{errCh: errCh})
	ts.Logf("tx-background: code=%s", ts.Getenv("HERMOD_CODE"))
}

// cmdTxWait waits for the background tx goroutine started by tx-background to
// complete and fails the test if tx exits with an error.
//
// Usage in .txtar:
//
//	tx-wait
func cmdTxWait(ts *testscript.TestScript, neg bool, _ []string) {
	key := ts.MkAbs(".")
	val, ok := txStateMap.LoadAndDelete(key)
	if !ok {
		ts.Fatalf("tx-wait: no background tx running; call tx-background first")
	}
	state := val.(*txState)

	select {
	case txErr := <-state.errCh:
		if txErr != nil {
			ts.Fatalf("tx-wait: tx exited with error: %v", txErr)
		}
	case <-time.After(20 * time.Second):
		ts.Fatalf("tx-wait: timed out waiting for tx to finish")
	}
}
