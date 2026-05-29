// Package cli: integration tests that drive runTx/runRx through the full
// network stack using a local signaling server.  Running these tests inside
// the cli package means the executed code counts toward internal/cli coverage.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/server"
)

// startLocalServer spins up a signaling server on a random port and returns
// its wss:// URL.  The server is shut down via t.Cleanup.
func startLocalServer(t *testing.T) string {
	t.Helper()
	cfg := config.Default()
	if err := config.GenerateServerCert(cfg); err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	tlsCert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		t.Fatalf("load tls cert: %v", err)
	}
	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	store := server.NewMemoryStore()
	rl := server.NewRateLimiter(100, 1000)
	srv := server.NewServer(store, rl, 60*time.Second, slog.Default())

	// Pick a free port, then release the listener so the server can bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.ListenAndServe(ctx, addr, tlsCfg) //nolint:errcheck

	// Wait until the port is accepting connections (up to 1.5 s).
	for i := 0; i < 30; i++ {
		time.Sleep(50 * time.Millisecond)
		c, err2 := net.Dial("tcp", addr)
		if err2 == nil {
			c.Close()
			return "wss://" + addr
		}
	}
	t.Fatal("local signaling server did not start")
	return ""
}

// cliTransferInternal runs tx and rx concurrently via ExecuteArgs and returns
// the bytes received by rx.  txArgs are appended after the standard tx flags.
// If stdinData is non-nil it is piped into stdin for the tx invocation.
func cliTransferInternal(t *testing.T, serverURL string, txArgs []string, stdinData []byte) []byte {
	t.Helper()

	destDir := t.TempDir()

	// Redirect stdout so we can capture the transfer code printed by tx.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	// Optional stdin pipe.
	if stdinData != nil {
		stdinR, stdinW, err2 := os.Pipe()
		if err2 != nil {
			t.Fatalf("stdin pipe: %v", err2)
		}
		stdinW.Write(stdinData)
		stdinW.Close()
		old := os.Stdin
		os.Stdin = stdinR
		t.Cleanup(func() {
			os.Stdin = old
			stdinR.Close()
		})
	}

	codeCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdoutR)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
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

	txErrCh := make(chan error, 1)
	oldStdout := os.Stdout
	os.Stdout = stdoutW
	go func() {
		allArgs := append([]string{"hermod", "tx", "--server", serverURL, "--words", "3"}, txArgs...)
		txErrCh <- ExecuteArgs(allArgs)
		stdoutW.Close()
		os.Stdout = oldStdout
	}()

	var code string
	select {
	case c, ok := <-codeCh:
		if !ok || c == "" {
			t.Fatal("did not receive transfer code from tx")
		}
		code = c
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for transfer code from tx")
	}

	rxArgs := []string{"hermod", "rx", "--server", serverURL, "--destination", destDir, code}
	if err := ExecuteArgs(rxArgs); err != nil {
		t.Fatalf("rx error: %v", err)
	}

	if err := <-txErrCh; err != nil {
		t.Fatalf("tx error: %v", err)
	}

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

// TestTransfer_Text_Internal covers the KindText path through runTx and runRx.
func TestTransfer_Text_Internal(t *testing.T) {
	serverURL := startLocalServer(t)
	want := "Hello from Hermod internal CLI coverage test"
	got := cliTransferInternal(t, serverURL, []string{want}, nil)
	if string(got) != want {
		t.Fatalf("text mismatch:\n got: %q\nwant: %q", string(got), want)
	}
}

// TestTransfer_File_Internal covers the KindFile path through runTx and runRx.
func TestTransfer_File_Internal(t *testing.T) {
	serverURL := startLocalServer(t)

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "data.bin")
	content := make([]byte, 4096)
	rand.Read(content)
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	got := cliTransferInternal(t, serverURL, []string{srcPath}, nil)
	if !bytes.Equal(got, content) {
		t.Fatalf("file content mismatch: got %d bytes, want %d", len(got), len(content))
	}
}

// TestTransfer_Stdin_Internal covers the KindStream (stdin) path.
func TestTransfer_Stdin_Internal(t *testing.T) {
	serverURL := startLocalServer(t)
	stdinData := []byte("stdin payload via internal cli coverage test")
	got := cliTransferInternal(t, serverURL, []string{}, stdinData)
	if !bytes.Equal(got, stdinData) {
		t.Fatalf("stdin mismatch:\n got: %q\nwant: %q", string(got), string(stdinData))
	}
}

// TestTransfer_SASVerify_Internal covers the --verify (SAS out-of-band) path through
// runTx and runRx, as well as the performSASCoordinated success path.
// openTTYFunc is overridden so each call gets a fresh pipe pre-filled with "y\n",
// removing the need for a real terminal in the test environment.
func TestTransfer_SASVerify_Internal(t *testing.T) {
	origOpenTTYFunc := openTTYFunc
	defer func() { openTTYFunc = origOpenTTYFunc }()

	openTTYFunc = func() (*os.File, error) {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		if _, err := w.WriteString("y\n"); err != nil {
			r.Close()
			return nil, err
		}
		w.Close()
		return r, nil
	}

	serverURL := startLocalServer(t)
	destDir := t.TempDir()
	want := "SAS verified transfer payload"

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	codeCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdoutR)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
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

	txErrCh := make(chan error, 1)
	oldStdout := os.Stdout
	os.Stdout = stdoutW
	go func() {
		allArgs := []string{"hermod", "tx", "--server", serverURL, "--words", "3", "--verify", want}
		txErrCh <- ExecuteArgs(allArgs)
		stdoutW.Close()
		os.Stdout = oldStdout
	}()

	var code string
	select {
	case c, ok := <-codeCh:
		if !ok || c == "" {
			t.Fatal("did not receive transfer code from tx (SAS)")
		}
		code = c
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for transfer code from tx (SAS)")
	}

	rxArgs := []string{"hermod", "rx", "--server", serverURL, "--destination", destDir, "--verify", code}
	if err := ExecuteArgs(rxArgs); err != nil {
		t.Fatalf("rx error (SAS): %v", err)
	}

	if err := <-txErrCh; err != nil {
		t.Fatalf("tx error (SAS): %v", err)
	}

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
			if string(data) != want {
				t.Fatalf("SAS transfer content mismatch: got %q, want %q", string(data), want)
			}
			return
		}
	}
	t.Fatalf("no file found in %s after SAS transfer", destDir)
}
