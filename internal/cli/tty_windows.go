// Package cli: TTY open for Windows.
//go:build windows

package cli

import "os"

// openTTY opens CON (the Windows console device) for reading user input
// directly from the terminal, bypassing any stdin redirection or pipe.
func openTTY() (*os.File, error) {
	return os.Open("CONIN$")
}
