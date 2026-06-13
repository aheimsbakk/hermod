package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// TestStreamBarFinishNewline verifies that streamBar.Finish() always outputs
// a single \n to terminate the progress bar line.
func TestStreamBarFinishNewline(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	b := newStreamBar()
	b.Write([]byte("test data"))
	b.Finish()

	w.Close()
	out, _ := io.ReadAll(r)

	if strings.Count(string(out), "\n") != 1 {
		t.Errorf("streamBar.Finish() produced %d newlines (want 1):\n%q",
			strings.Count(string(out), "\n"), string(out))
	}
}

// TestHashBarCancelNewline verifies that newHashBar does NOT output a trailing
// \n on partial writes, so the cancel handler's \n correctly terminates the
// \r-based bar line without creating a blank line.
func TestHashBarCancelNewline(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	bar := newHashBar(100, "receiving")
	bar.Write(make([]byte, 50))
	fmt.Fprint(os.Stderr, "\n")

	w.Close()
	out, _ := io.ReadAll(r)

	// The hash bar uses \r (no trailing \n). A single \n must be the only
	// newline — no blank line (\n\n).
	if strings.Contains(string(out), "\n\n") {
		t.Errorf("hash bar cancel produced blank line (consecutive \\n):\n%q", string(out))
	}
	if !strings.HasSuffix(string(out), "\n") {
		t.Errorf("hash bar cancel output must end with \\n:\n%q", string(out))
	}
}

// TestHashBarSuccessNewline verifies that newHashBar does output a trailing \n
// on completion (the OnCompletion callback fires at 100%).
func TestHashBarSuccessNewline(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	bar := newHashBar(50, "testing")
	bar.Write(make([]byte, 50))
	bar.Close()

	w.Close()
	out, _ := io.ReadAll(r)

	if !strings.HasSuffix(string(out), "\n") {
		t.Errorf("hash bar success output must end with \\n:\n%q", string(out))
	}
}

// TestStreamBarOnlyOneNewlineAfterFinish ensures that cancel handler adding
// \n after streamBar.Finish() creates two newlines — a blank line (the bug).
func TestStreamBarDoubleNewlineOnCancel(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	// Simulate stream-bar path: finish + cancel handler \n
	b := newStreamBar()
	b.Write([]byte("test data"))
	b.Finish()
	fmt.Fprint(os.Stderr, "\n")

	w.Close()
	out, _ := io.ReadAll(r)

	// Finish() prints 1 \n, then the extra \n makes 2 total.
	// This is the bug — the fix prevents the cancel handler's \n.
	count := strings.Count(string(out), "\n")
	if count != 2 {
		t.Errorf("stream bar finish + cancel \\n: got %d newlines (want 2 for bug, 1 after fix):\n%q",
			count, string(out))
	}
}
