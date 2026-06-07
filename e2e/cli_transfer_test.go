// Package e2e: CLI-level end-to-end transfer tests.
// Each test drives the real cli.ExecuteArgs() path for tx and rx concurrently.
package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hermod/hermod/internal/cli"
	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/server"
)

// startCLIServer starts a signaling server and returns its wss:// URL and the
// SHA-256 certificate fingerprint.  The server is shut down via t.Cleanup.
func startCLIServer(t *testing.T) (serverURL, fingerprint string) {
	t.Helper()
	cfg := config.Default()
	if err := config.GenerateServerCert(cfg); err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	tlsCert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	store := server.NewMemoryStore()
	rl := server.NewRateLimiter(100, 1000)
	srv := server.NewServer(store, rl, 60*time.Second, server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures, nil, slog.Default())

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.ListenAndServe(ctx, addr, tlsCfg)

	for i := 0; i < 30; i++ {
		time.Sleep(50 * time.Millisecond)
		c, err2 := net.Dial("tcp", addr)
		if err2 == nil {
			c.Close()
			fp := config.CertFingerprint(tlsCert.Certificate[0])
			return "wss://" + addr, fp
		}
	}
	t.Fatal("signaling server did not start")
	return "", ""
}

// trustServerForCLITest redirects config to a fresh temp directory, pins
// serverURL with fingerprint, and sets HOME so that cli.ExecuteArgs picks up
// the trusted-server entry during this test.
func trustServerForCLITest(t *testing.T, serverURL, fingerprint string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HERMOD_SERVER", "")

	cfg := config.Default()
	cfg.ServerURL = serverURL
	config.PinServer(cfg, serverURL, fingerprint)
	if err := config.Save(cfg); err != nil {
		t.Fatalf("save trusted-server config: %v", err)
	}
}

// cliTransfer runs tx and rx concurrently via cli.ExecuteArgs.
// txArgs are the arguments after "tx" (e.g. a file path or text string).
// stdinData, if non-nil, is piped into stdin for tx (stdin mode).
// fingerprint is the server's certificate fingerprint; it is pinned in a temp
// config so that the trusted-server check passes.
// Returns the bytes saved to destDir by rx.
func cliTransfer(t *testing.T, serverURL, fingerprint string, txArgs []string, stdinData []byte) []byte {
	t.Helper()
	trustServerForCLITest(t, serverURL, fingerprint)

	destDir := t.TempDir()

	// Pipe stdout so we can read the transfer code while tx is still running.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	// Optional stdin pipe for stdin mode.
	var oldStdin *os.File
	if stdinData != nil {
		stdinR, stdinW, err2 := os.Pipe()
		if err2 != nil {
			t.Fatalf("stdin pipe: %v", err2)
		}
		stdinW.Write(stdinData)
		stdinW.Close()
		oldStdin = os.Stdin
		os.Stdin = stdinR
		t.Cleanup(func() {
			os.Stdin = oldStdin
			stdinR.Close()
		})
	}

	// codeCh receives the transfer code as soon as tx prints it.
	codeCh := make(chan string, 1)

	// Read stdout line-by-line in a goroutine; extract the transfer code.
	go func() {
		scanner := bufio.NewScanner(stdoutR)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// tx prints: "Transfer code: 3-word-word-word"
			if strings.HasPrefix(line, "Transfer code:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					codeCh <- strings.TrimSpace(parts[1])
				}
			}
		}
		close(codeCh)
		stdoutR.Close()
	}()

	// Run tx, capturing its stdout and stderr output.
	txErrCh := make(chan error, 1)
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	os.Stdout = stdoutW
	os.Stderr = stdoutW
	go func() {
		allArgs := append([]string{"hermod", "tx", "--server", serverURL, "--words", "3"}, txArgs...)
		txErrCh <- cli.ExecuteArgs(allArgs)
		stdoutW.Close()
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	// Wait for the transfer code (with timeout).
	var code string
	select {
	case c, ok := <-codeCh:
		if !ok || c == "" {
			t.Fatal("did not receive transfer code from tx")
		}
		code = c
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for transfer code")
	}

	// Run rx with the code.
	rxArgs := []string{"hermod", "rx", "--server", serverURL, "--destination", destDir, code}
	if err := cli.ExecuteArgs(rxArgs); err != nil {
		t.Fatalf("rx error: %v", err)
	}

	// Wait for tx to finish.
	if err := <-txErrCh; err != nil {
		t.Fatalf("tx error: %v", err)
	}

	// Read the file written by rx.
	entries, err := os.ReadDir(destDir)
	if err != nil {
		t.Fatalf("read dest dir: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			data, err := os.ReadFile(filepath.Join(destDir, e.Name()))
			if err != nil {
				t.Fatalf("read received file: %v", err)
			}
			return data
		}
	}
	t.Fatalf("no file found in %s", destDir)
	return nil
}

// TestCLITransferText sends a short text string end-to-end via the CLI.
func TestCLITransferText(t *testing.T) {
	serverURL, fp := startCLIServer(t)
	want := "Hello from Hermod CLI text transfer"

	got := cliTransfer(t, serverURL, fp, []string{want}, nil)

	if string(got) != want {
		t.Fatalf("text mismatch:\n got: %q\nwant: %q", string(got), want)
	}
}

// TestCLITransferFile sends a binary file end-to-end via the CLI.
func TestCLITransferFile(t *testing.T) {
	serverURL, fp := startCLIServer(t)

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "payload.bin")
	content := make([]byte, 4096)
	rand.Read(content)
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	got := cliTransfer(t, serverURL, fp, []string{srcPath}, nil)

	if !bytes.Equal(got, content) {
		t.Fatalf("file content mismatch: got %d bytes, want %d", len(got), len(content))
	}
}

// TestCLITransferStdin pipes data through stdin end-to-end via the CLI.
func TestCLITransferStdin(t *testing.T) {
	serverURL, fp := startCLIServer(t)
	stdinData := []byte("stdin payload: Hermod CLI end-to-end test")

	got := cliTransfer(t, serverURL, fp, []string{}, stdinData)

	if !bytes.Equal(got, stdinData) {
		t.Fatalf("stdin mismatch:\n got: %q\nwant: %q", string(got), string(stdinData))
	}
}

// Ensure unused imports don't cause build failures.
var _ = fmt.Sprintf
var _ context.Context
