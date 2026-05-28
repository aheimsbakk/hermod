//go:build linux || darwin

package network

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// udpControl sets SO_REUSEADDR and SO_REUSEPORT on the socket.
func udpControl(network, address string, c syscall.RawConn) error {
	var setSockOptErr error
	err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			setSockOptErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			setSockOptErr = err
		}
	})
	if err != nil {
		return err
	}
	return setSockOptErr
}
