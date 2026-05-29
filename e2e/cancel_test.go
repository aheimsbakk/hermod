// Package e2e: cancellation tests for tx and rx commands.
// Verifies that Ctrl+C on either side cleans up temp files and exits gracefully.
package e2e_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hermod/hermod/internal/cli"
)

// TestRxCancelCleansUpTempFile verifies that when the receiver cancels mid-transfer,
// no .hermod_tmp file is left in the destination directory.
func TestRxCancelCleansUpTempFile(t *testing.T) {
	serverURL := startCLIServer(t)

	// Use 16 MiB so the transfer cannot complete before we confirm rx is mid-receive.
	// A 1 MiB file finishes in <300 ms over loopback, causing SIGINT to race with
	// signal.NotifyContext teardown and kill the test binary.
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "bigfile.bin")
	content := make([]byte, 16<<20) // 16 MiB
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	destDir := t.TempDir()

	// Capture stdout to extract the transfer code.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
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

	// Run tx in background.
	txErrCh := make(chan error, 1)
	oldStdout := os.Stdout
	os.Stdout = stdoutW
	go func() {
		args := []string{"hermod", "tx", "--server", serverURL, "--words", "3", srcPath}
		txErrCh <- cli.ExecuteArgs(args)
		stdoutW.Close()
		os.Stdout = oldStdout
	}()

	// Wait for transfer code.
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

	// Run rx in a goroutine; interrupt the process shortly after rx starts.
	rxErrCh := make(chan error, 1)
	go func() {
		args := []string{"hermod", "rx", "--server", serverURL, "--destination", destDir, code}
		rxErrCh <- cli.ExecuteArgs(args)
	}()

	// Poll until rx has created the temp file, then send SIGINT.
	// This replaces the fixed 300 ms sleep and eliminates the race:
	// if the transfer finishes before the sleep elapses, SIGINT would
	// hit the test binary's default handler and kill the process.
	tmpFound := make(chan struct{}, 1)
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.After(8 * time.Second)
		for {
			select {
			case <-deadline:
				tmpFound <- struct{}{}
				return
			case <-ticker.C:
				entries, _ := os.ReadDir(destDir)
				for _, e := range entries {
					if strings.HasSuffix(e.Name(), ".hermod_tmp") {
						tmpFound <- struct{}{}
						return
					}
				}
			}
		}
	}()
	<-tmpFound // wait for temp file to appear (or 8 s deadline)

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("find process: %v", err)
	}
	if err := proc.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}

	// Both sides should exit within a reasonable time.
	timeout := time.After(10 * time.Second)
	rxDone, txDone := false, false
	for !rxDone || !txDone {
		select {
		case <-rxErrCh:
			rxDone = true
		case <-txErrCh:
			txDone = true
		case <-timeout:
			t.Fatal("timed out waiting for tx/rx to exit after cancellation")
		}
	}

	// No .hermod_tmp files must remain in destDir.
	entries, err := os.ReadDir(destDir)
	if err != nil {
		t.Fatalf("read dest dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".hermod_tmp") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}
