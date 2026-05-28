//go:build windows

package network

import "syscall"

// udpControl is a no-op on Windows (SO_REUSEPORT is not supported).
func udpControl(network, address string, c syscall.RawConn) error {
	return nil
}
