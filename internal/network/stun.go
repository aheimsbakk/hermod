package network

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/hermod/hermod/internal/server"
)

// reflectCookieMagic is the first byte of a cookie response from the server.
const reflectCookieMagic = 0x10

// ServerUDPAddr extracts the UDP host:port from a WebSocket server URL,
// using the same host and port for UDP. For example:
//
//	"wss://relay.example.com:4376" → "relay.example.com:4376"
//	"wss://localhost:4376"         → "localhost:4376"
func ServerUDPAddr(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	host := u.Host
	if host == "" {
		return "", fmt.Errorf("empty host in server URL: %s", serverURL)
	}
	return host, nil
}

// DiscoverViaReflector sends a reflection probe to serverAddr using the
// given UDP conn and returns the external UDP address observed by the server.
// serverAddr should point to the signaling server's UDP reflection port
// (typically the same host and port as the WebSocket URL).
//
// The protocol uses a two-phase cookie handshake to prevent UDP amplification:
//
// Phase 1 — client sends [0x10] (cookie request, 1 byte).
// Server responds with [0x10][HMAC(secret, IP)[:8]] (cookie, 9 bytes).
//
// Phase 2 — client echoes [0x10][cookie] (9 bytes).
// Server verifies HMAC, responds with external address (7-19 bytes).
//
// Legacy servers that don't support cookies respond directly with the
// external address (first byte 0x04 or 0x06). The client handles both.
func DiscoverViaReflector(conn net.PacketConn, serverAddr string, timeout time.Duration) (*net.UDPAddr, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve reflector address %s: %w", serverAddr, err)
	}

	// Phase 1: send cookie-mode probe.
	probe := []byte{reflectCookieMagic}
	if _, err := conn.WriteTo(probe, udpAddr); err != nil {
		return nil, fmt.Errorf("send probe: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("read probe response: %w", err)
	}

	// Cookie response: first byte matches the magic, should be 9 bytes.
	if n != 9 || buf[0] != reflectCookieMagic {
		return nil, fmt.Errorf("unexpected reflector response: %x", buf[:n])
	}

	// Phase 2: echo cookie back to verify we can receive at this address.
	echo := make([]byte, 9)
	echo[0] = reflectCookieMagic
	copy(echo[1:], buf[1:9])
	if _, err := conn.WriteTo(echo, udpAddr); err != nil {
		return nil, fmt.Errorf("send cookie echo: %w", err)
	}

	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("read address response: %w", err)
	}

	return server.DecodeExternalAddress(buf[:n])
}
