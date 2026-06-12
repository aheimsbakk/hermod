package network

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/hermod/hermod/internal/server"
)

// STUN protocol constants (RFC 5389).
const (
	stunMagicCookie   = 0x2112A442
	stunBindingReq    = 0x0001
	stunBindingResp   = 0x0101
	stunAttrXORMapped = 0x0020
	stunHeaderLen     = 20
)

// DefaultSTUNServer is the default STUN server for NAT address discovery.
const DefaultSTUNServer = "stun.l.google.com:19302"

// ReflectRequest is a 1-byte UDP cookie-mode probe sent to the signaling
// server's UDP reflection endpoint. The server responds with an HMAC cookie
// that the client must echo before receiving the external address.
var ReflectRequest = []byte{0x10}

// reflectCookieMagic is the first byte of a cookie response from the server.
const reflectCookieMagic = 0x10

// stunTXID is a 12-byte STUN transaction identifier.
type stunTXID [12]byte

// DiscoverExternalAddress sends a STUN binding request from conn to the
// STUN server at serverAddr. It returns the external IP:port as observed
// by the STUN server, or an error if discovery fails.
//
// The caller should provide a timeout of at least a few seconds.
// Pass IPFamilyAny if the socket is dual-stack.
func DiscoverExternalAddress(conn net.PacketConn, serverAddr string, timeout time.Duration) (*net.UDPAddr, error) {
	udpServerAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve STUN server %s: %w", serverAddr, err)
	}

	var txID stunTXID
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, fmt.Errorf("generate transaction ID: %w", err)
	}

	// Build STUN binding request — 20-byte header, no attributes.
	req := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(req[0:2], stunBindingReq)
	binary.BigEndian.PutUint16(req[2:4], 0) // length
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txID[:])

	if _, err := conn.WriteTo(req, udpServerAddr); err != nil {
		return nil, fmt.Errorf("send STUN request: %w", err)
	}

	// Read response with deadline.
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("read STUN response: %w", err)
	}

	return parseSTUNResponse(buf[:n], txID)
}

// parseSTUNResponse verifies the response and extracts the external address.
func parseSTUNResponse(data []byte, txID stunTXID) (*net.UDPAddr, error) {
	if len(data) < stunHeaderLen {
		return nil, fmt.Errorf("STUN response too short: %d bytes", len(data))
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunBindingResp {
		return nil, fmt.Errorf("unexpected STUN message type: 0x%04x", msgType)
	}

	// Verify transaction ID matches our request.
	var gotTXID stunTXID
	copy(gotTXID[:], data[8:20])
	if gotTXID != txID {
		return nil, fmt.Errorf("STUN transaction ID mismatch")
	}

	return parseXORMappedAddress(data[stunHeaderLen:], txID)
}

// parseXORMappedAddress walks STUN attributes and returns the first
// XOR-MAPPED-ADDRESS found.
func parseXORMappedAddress(attrs []byte, txID stunTXID) (*net.UDPAddr, error) {
	pos := 0
	for pos+4 <= len(attrs) {
		attrType := binary.BigEndian.Uint16(attrs[pos:])
		attrLen := int(binary.BigEndian.Uint16(attrs[pos+2:]))
		pos += 4

		if attrLen > len(attrs)-pos {
			break
		}

		if attrType == stunAttrXORMapped {
			return decodeXORMappedAddress(attrs[pos:pos+attrLen], txID)
		}

		pos += attrLen
		// Align to 4-byte boundary for next attribute header.
		if pad := pos % 4; pad != 0 {
			pos += 4 - pad
		}
	}
	return nil, fmt.Errorf("no XOR-MAPPED-ADDRESS in STUN response")
}

// xorMagicIP returns the 4-byte XOR mask for IPv4-mapped portions of
// XOR-MAPPED-ADDRESS: the STUN magic cookie in network byte order.
// Uses uint32 arithmetic so byte truncation is valid at runtime.
func xorMagicIP() [4]byte {
	c := uint32(stunMagicCookie)
	return [4]byte{
		byte(c >> 24),
		byte(c >> 16),
		byte(c >> 8),
		byte(c),
	}
}

// xorMagicPort returns the 2-byte XOR mask for the port field:
// the most significant 16 bits of the STUN magic cookie.
func xorMagicPort() uint16 {
	return uint16(uint32(stunMagicCookie) >> 16)
}

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

	// Legacy server: response starts with address family byte (0x04 or 0x06).
	if len(buf) > 0 && (buf[0] == 4 || buf[0] == 6) {
		return server.DecodeExternalAddress(buf[:n])
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

// decodeXORMappedAddress decodes an XOR-MAPPED-ADDRESS attribute body
// (RFC 5389 section 15.2).
func decodeXORMappedAddress(data []byte, txID stunTXID) (*net.UDPAddr, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("XOR-MAPPED-ADDRESS too short")
	}

	family := data[1]
	xorPort := binary.BigEndian.Uint16(data[2:4])
	port := int(xorPort ^ xorMagicPort())
	mask := xorMagicIP()

	switch family {
	case 0x01: // IPv4
		if len(data) < 8 {
			return nil, fmt.Errorf("XOR-MAPPED-ADDRESS too short for IPv4")
		}
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = data[4+i] ^ mask[i]
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil

	case 0x02: // IPv6
		if len(data) < 20 {
			return nil, fmt.Errorf("XOR-MAPPED-ADDRESS too short for IPv6")
		}
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			ip[i] = data[4+i] ^ mask[i]
		}
		for i := 4; i < 16; i++ {
			ip[i] = data[4+i] ^ txID[i-4]
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil

	default:
		return nil, fmt.Errorf("unknown address family: 0x%02x", family)
	}
}
