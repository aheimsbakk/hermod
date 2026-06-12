// Package server: UDP reflection endpoint for external address discovery.
//
// # Security: reflection / amplification attacks
//
// This endpoint uses a two-phase stateless cookie handshake to prevent
// UDP reflection amplification entirely.
//
// Phase 1 (cookie request):    [0x10]               (1 byte)
// Phase 1 response (server):   [0x10][cookie(8)]    (9 bytes)
// Phase 2 (verified request):  [0x10][cookie(8)]    (9 bytes)
// Phase 2 response (server):   [family][IP][port]   (7-19 bytes)
//
// The cookie is HMAC-SHA256(secretKey, sourceIP)[:8], bound to the
// source IP. An attacker who spoofs the source IP:
//   - Receives the cookie response (9 bytes → 9× amplification, rate-limited)
//   - Cannot complete phase 2 because they never received the cookie
//   - The external address is NEVER sent to an unverified source
//
// The secret key is rotated every UTC calendar day. Old keys are accepted
// for a 5-minute grace period to handle clock skew.
package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	udpReflectTimeout     = 2 * time.Second
	udpReflectMaxPacket   = 512
	udpReflectRate        = 10
	udpReflectBurst       = 5
	reflectCookieSize     = 8
	reflectKeyGracePeriod = 5 * time.Minute
)

// reflectProbeMagic is the first byte of a cookie-mode probe.
const reflectProbeMagic = 0x10

// reflectCookieMagic is the first byte of a cookie response.
const reflectCookieMagic = 0x10

// udpReflector handles the UDP reflection endpoint.
type udpReflector struct {
	conn      net.PacketConn
	rl        *RateLimiter
	closeOnce sync.Once
	closed    chan struct{}

	mu      sync.Mutex
	key     []byte    // current HMAC key (32 bytes)
	oldKey  []byte    // previous key, accepted during grace period
	keyTime time.Time // when the current key was generated
}

// startUDPReflector opens a UDP socket on addr and returns a running reflector.
func startUDPReflector(ctx context.Context, addr string) *udpReflector {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		slog.Warn("UDP reflection not available — CGNAT clients may fail hole-punching",
			"addr", addr, "err", err)
		return nil
	}

	r := &udpReflector{
		conn:   pc,
		rl:     NewRateLimiter(udpReflectRate, udpReflectBurst),
		closed: make(chan struct{}),
	}
	r.rotateKey()
	go r.serve(ctx)
	return r
}

// rotateKey generates a fresh HMAC key. Must be called at startup and then
// daily. The old key is retained during the grace period so in-flight probes
// from just before the rotation still validate.
func (r *udpReflector) rotateKey() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.key != nil {
		r.oldKey = r.key
	}
	r.key = make([]byte, 32)
	if _, err := rand.Read(r.key); err != nil {
		panic("reflector: failed to generate HMAC key: " + err.Error())
	}
	r.keyTime = time.Now()
}

// computeCookie returns HMAC-SHA256(key, netIP)[:8].
func computeCookie(key []byte, ip net.IP) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(ip)
	return mac.Sum(nil)[:reflectCookieSize]
}

// verifyCookie checks if the given cookie matches any valid key for the IP.
func (r *udpReflector) verifyCookie(ip net.IP, cookie []byte) bool {
	if len(cookie) != reflectCookieSize {
		return false
	}
	r.mu.Lock()
	keys := [][]byte{r.key}
	if r.oldKey != nil && time.Since(r.keyTime) <= reflectKeyGracePeriod {
		keys = append(keys, r.oldKey)
	}
	r.mu.Unlock()

	for _, k := range keys {
		expected := computeCookie(k, ip)
		if hmac.Equal(expected, cookie) {
			return true
		}
	}
	return false
}

// serve reads UDP packets and handles the two-phase cookie protocol.
func (r *udpReflector) serve(ctx context.Context) {
	buf := make([]byte, udpReflectMaxPacket)
	for {
		select {
		case <-ctx.Done():
			r.Close()
			return
		default:
		}

		// Check for daily key rotation.
		if time.Since(r.keyTime) > 24*time.Hour {
			r.rotateKey()
		}

		if err := r.conn.SetReadDeadline(time.Now().Add(udpReflectTimeout)); err != nil {
			continue
		}

		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}

		udpAddr := addr.(*net.UDPAddr)
		firstByte := buf[0]

		switch {
		case firstByte == reflectProbeMagic && n == 1:
			// Cookie request — respond with HMAC cookie.
			if !r.rl.Allow(udpAddr.IP.String()) {
				slog.Warn("UDP reflection rate-limited (cookie req)", "remote_ip", udpAddr.IP)
				continue
			}
			cookie := computeCookie(r.key, udpAddr.IP)
			resp := make([]byte, 1+reflectCookieSize)
			resp[0] = reflectCookieMagic
			copy(resp[1:], cookie)
			_, _ = r.conn.WriteTo(resp, addr)

		case firstByte == reflectProbeMagic && n == 1+reflectCookieSize && r.verifyCookie(udpAddr.IP, buf[1:1+reflectCookieSize]):
			// Verified cookie echo — respond with external address.
			// No rate limit: this phase is only reached by a client that
			// completed the cookie challenge, proving they can receive
			// packets at this source address.
			r.writeAddress(udpAddr)

		default:
			// Silently drop anything that doesn't match a valid protocol
			// state. This prevents the endpoint from being used as a
			// generic reflection amplifier for arbitrary payloads.
		}
	}
}

// writeAddress sends the external address to the peer.
func (r *udpReflector) writeAddress(addr *net.UDPAddr) {
	resp := encodeExternalAddress(addr)
	if resp != nil {
		_, _ = r.conn.WriteTo(resp, addr)
	}
}

// Close shuts down the UDP reflector and its socket.
func (r *udpReflector) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		close(r.closed)
		r.conn.Close()
	})
}

// encodeExternalAddress returns a binary-encoded external address.
func encodeExternalAddress(addr *net.UDPAddr) []byte {
	if addr == nil {
		return nil
	}
	ip4 := addr.IP.To4()
	if ip4 != nil {
		buf := make([]byte, 7)
		buf[0] = 4
		copy(buf[1:5], ip4)
		binary.BigEndian.PutUint16(buf[5:7], uint16(addr.Port))
		return buf
	}
	ip6 := addr.IP.To16()
	if ip6 != nil {
		buf := make([]byte, 19)
		buf[0] = 6
		copy(buf[1:17], ip6)
		binary.BigEndian.PutUint16(buf[17:19], uint16(addr.Port))
		return buf
	}
	return nil
}

// DecodeExternalAddress decodes a binary-encoded external address.
func DecodeExternalAddress(data []byte) (*net.UDPAddr, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("external address data too short")
	}
	switch data[0] {
	case 4:
		if len(data) < 7 {
			return nil, fmt.Errorf("IPv4 external address too short: %d bytes", len(data))
		}
		ip := net.IP(data[1:5])
		port := int(binary.BigEndian.Uint16(data[5:7]))
		return &net.UDPAddr{IP: ip, Port: port}, nil
	case 6:
		if len(data) < 19 {
			return nil, fmt.Errorf("IPv6 external address too short: %d bytes", len(data))
		}
		ip := net.IP(data[1:17])
		port := int(binary.BigEndian.Uint16(data[17:19]))
		return &net.UDPAddr{IP: ip, Port: port}, nil
	default:
		return nil, fmt.Errorf("unknown address family in external address: %d", data[0])
	}
}
