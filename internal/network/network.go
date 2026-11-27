// Package network implements UDP multiplexing, NAT hole punching, and QUIC transport.
package network

import (
	"context"
	"fmt"
	"net"
)

// BindUDP binds a UDP socket on the given address (":0" for OS-assigned port).
// SO_REUSEADDR/SO_REUSEPORT are set via udpControl (platform-specific file).
// The receive buffer is increased to 2 MiB so that quic-go does not log a
// warning about the default OS buffer size. If the type assertion to
// *net.UDPConn fails (very unlikely with stdlib sockets), the buffer stays
// at the OS default — the connection still works, just potentially slower
// on high-bandwidth links.
func BindUDP(addr string) (net.PacketConn, error) {
	lc := &net.ListenConfig{
		Control: udpControl,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind UDP socket on %s: %w", addr, err)
	}
	if udpConn, ok := conn.(*net.UDPConn); ok {
		// Ignore errors — the OS may enforce a system-wide maximum that is
		// lower than 2 MiB (e.g. `net.core.rmem_max` sysctl on Linux).
		_ = udpConn.SetReadBuffer(2 << 20)  // 2 MiB
		_ = udpConn.SetWriteBuffer(2 << 20) // 2 MiB
	}
	return conn, nil
}

// LocalUDPAddr returns the local endpoint as a *net.UDPAddr.
func LocalUDPAddr(conn net.PacketConn) (*net.UDPAddr, error) {
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("local address is not a UDP socket")
	}
	return addr, nil
}
