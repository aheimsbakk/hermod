// Package hermod_test: lint checks for dead code and unused symbols.
// Runs deadcode and staticcheck as part of the normal test suite.
package hermod_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func skipIfDisabled(t *testing.T) {
	t.Helper()
	if os.Getenv("HERMOD_SKIP_LINT") != "" {
		t.Skip("HERMOD_SKIP_LINT is set")
	}
}

// findModuleRoot walks up from the test source to find go.mod.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	_, src, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source")
	}
	dir := filepath.Dir(src)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// runGoRun runs `go run <tool@version>` with the given args from the module root.
// Returns stdout+stderr combined. Does not fail the test on non-zero exit.
func runGoRun(t *testing.T, tool string, args ...string) string {
	t.Helper()
	root := findModuleRoot(t)
	cmd := exec.Command("go", append([]string{"run", tool}, args...)...)
	cmd.Dir = root
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// TestDeadCode verifies there are no unreachable functions or unused exports.
func TestDeadCode(t *testing.T) {
	skipIfDisabled(t)
	output := runGoRun(t, "golang.org/x/tools/cmd/deadcode@latest", "-test", "./...")
	// Filter out Go toolchain version-switch lines (stderr bleeds into CombinedOutput).
	lines := strings.Split(output, "\n")
	var findings []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "go:") {
			continue
		}
		findings = append(findings, trimmed)
	}
	if len(findings) > 0 {
		t.Errorf("deadcode found issues:\n%s", strings.Join(findings, "\n"))
	}
}

// TestStaticcheckUnused verifies there are no unused symbols (U1000).
func TestStaticcheckUnused(t *testing.T) {
	skipIfDisabled(t)
	output := runGoRun(t, "honnef.co/go/tools/cmd/staticcheck@latest", "./...")
	// Filter output for U1000 (unused) diagnostics only.
	lines := strings.Split(output, "\n")
	var unused []string
	for _, line := range lines {
		if strings.Contains(line, "U1000") {
			unused = append(unused, line)
		}
	}
	if len(unused) > 0 {
		t.Errorf("staticcheck found unused symbols (U1000):\n%s", strings.Join(unused, "\n"))
	}
}
