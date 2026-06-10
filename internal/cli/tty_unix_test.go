//go:build !windows

package cli

import (
	"testing"
)

func TestOpenTTY(t *testing.T) {
	f, err := openTTY()
	if err != nil {
		t.Skipf("openTTY: %v (no /dev/tty in this environment)", err)
	}
	defer f.Close()
	if f == nil {
		t.Fatal("expected non-nil file from openTTY")
	}
}
