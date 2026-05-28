// Package cli: TTY open for Unix/Linux/macOS.
//go:build !windows

package cli

import "os"

// openTTY opens /dev/tty for reading user input directly from the terminal,
// bypassing any stdin redirection or pipe. This ensures the SAS verification
// prompt is read from the real controlling terminal even when stdin is piped.
func openTTY() (*os.File, error) {
	return os.Open("/dev/tty")
}
