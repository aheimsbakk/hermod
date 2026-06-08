// Package network implements UDP multiplexing, NAT hole punching, and QUIC transport.
package network

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// packetMux multiplexes a single UDP socket between QUIC traffic and
// custom probe packets used for NAT hole punching.
//
// Probe packets: first byte == probeMarker (0x01).
// QUIC packets: everything else (QUIC headers start with 0x40+ or 0xC0+).
type packetMux struct {
	conn      net.PacketConn
	quicCh    chan udpDatagram
	probeCh   chan udpDatagram
	closeOnce sync.Once
	closed    chan struct{}
}

type udpDatagram struct {
	data []byte
	addr net.Addr
}

const probeMarker byte = 0x01

// NewPacketMux wraps a PacketConn and starts the demux loop.
func NewPacketMux(conn net.PacketConn) *packetMux {
	m := &packetMux{
		conn:    conn,
		quicCh:  make(chan udpDatagram, 256),
		probeCh: make(chan udpDatagram, 64),
		closed:  make(chan struct{}),
	}
	go m.readLoop()
	return m
}

func (m *packetMux) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if n > 0 && pkt[0] == probeMarker {
			select {
			case m.probeCh <- udpDatagram{data: pkt, addr: addr}:
			default:
			}
		} else {
			select {
			case m.quicCh <- udpDatagram{data: pkt, addr: addr}:
			default:
			}
		}
	}
}

// Close shuts down the mux and its underlying connection.
func (m *packetMux) Close() {
	m.closeOnce.Do(func() {
		close(m.closed)
		m.conn.Close()
	})
}

// LocalAddr returns the local address of the underlying connection.
func (m *packetMux) LocalAddr() net.Addr {
	return m.conn.LocalAddr()
}

// muxedConn implements net.PacketConn backed by the QUIC channel of a packetMux.
type muxedConn struct {
	mux           *packetMux
	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *muxedConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Check whether a read deadline is set and build a timer channel.
	c.mu.Lock()
	dl := c.readDeadline
	c.mu.Unlock()

	var timerCh <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timerCh = time.After(d)
	}

	select {
	case <-c.mux.closed:
		return 0, nil, net.ErrClosed
	case <-timerCh:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt, ok := <-c.mux.quicCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n = copy(p, pkt.data)
		return n, pkt.addr, nil
	}
}

func (c *muxedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Check write deadline before delegating to the underlying connection.
	c.mu.Lock()
	dl := c.writeDeadline
	c.mu.Unlock()
	if !dl.IsZero() && time.Now().After(dl) {
		return 0, os.ErrDeadlineExceeded
	}
	return c.mux.conn.WriteTo(p, addr)
}

func (c *muxedConn) Close() error { return nil } // managed by mux
func (c *muxedConn) LocalAddr() net.Addr {
	return c.mux.conn.LocalAddr()
}
func (c *muxedConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
func (c *muxedConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}
func (c *muxedConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// BindUDP binds a UDP socket on the given address (":0" for OS-assigned port).
// SO_REUSEADDR/SO_REUSEPORT are set via udpControl (platform-specific file).
func BindUDP(addr string) (net.PacketConn, error) {
	lc := &net.ListenConfig{
		Control: udpControl,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind UDP socket on %s: %w", addr, err)
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

// HolePunchResult carries the outcome of NAT hole punching.
type HolePunchResult struct {
	PeerAddr *net.UDPAddr
}

// HolePunch performs simultaneous UDP hole punching to each candidate address.
// probeNonce is a 32-byte SHA-256 hash derived from the CPace shared key.
// The probe payload uses bytes [0:7] and the ack payload uses bytes [8:15],
// giving 64 bits of entropy per packet — practically unguessable by an
// off-path attacker and resistant to spoofed ack injection.
// Returns as soon as a probe/ack exchange succeeds or ctx is cancelled.
//
// probeCtx controls the probe-sending goroutine's lifetime separately from
// the hole-punch timeout. Pass a context that outlives the main ctx so
// probing continues after HolePunch returns, keeping NAT mappings alive
// until the caller signals completion (D-02). Pass ctx to use the same
// lifetime for both.
func HolePunch(ctx context.Context, probeCtx context.Context, mux *packetMux, candidates []*net.UDPAddr, probeNonce [32]byte) (*HolePunchResult, error) {
	if probeCtx == nil {
		probeCtx = ctx
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// probe = [probeMarker, nonce[0:7]]  — 8 bytes
	// ack   = [probeMarker, nonce[8:15]] — 8 bytes
	probe := []byte{probeMarker, probeNonce[0], probeNonce[1], probeNonce[2], probeNonce[3], probeNonce[4], probeNonce[5], probeNonce[6]}
	ack := []byte{probeMarker, probeNonce[8], probeNonce[9], probeNonce[10], probeNonce[11], probeNonce[12], probeNonce[13], probeNonce[14]}

	// Send probes to all candidates periodically.
	// Uses probeCtx so probing continues even after HolePunch returns,
	// preventing NAT mappings from expiring before the QUIC handshake.
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-probeCtx.Done():
				return
			case <-ticker.C:
				for _, addr := range candidates {
					mux.conn.WriteTo(probe, addr) //nolint:errcheck
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("UDP hole punch timed out: %w", ctx.Err())
		case pkt := <-mux.probeCh:
			if len(pkt.data) < 8 {
				continue
			}
			switch {
			case subtle.ConstantTimeCompare(pkt.data[1:8], probeNonce[:7]) == 1: // received probe — send ack
				mux.conn.WriteTo(ack, pkt.addr) //nolint:errcheck
				if udpAddr, ok := pkt.addr.(*net.UDPAddr); ok {
					return &HolePunchResult{PeerAddr: udpAddr}, nil
				}
			case subtle.ConstantTimeCompare(pkt.data[1:8], probeNonce[8:15]) == 1: // received ack
				if udpAddr, ok := pkt.addr.(*net.UDPAddr); ok {
					return &HolePunchResult{PeerAddr: udpAddr}, nil
				}
			}
		}
	}
}

// DialQUIC establishes a QUIC connection to peerAddr using the muxed conn.
// peerCertHash is the expected SHA-256 fingerprint (hex) of the peer's TLS certificate.
func DialQUIC(ctx context.Context, mux *packetMux, peerAddr *net.UDPAddr, baseTLS *tls.Config, peerCertHash string) (*quic.Conn, error) {
	tlsCfg := baseTLS.Clone()
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.VerifyPeerCertificate = makeCertPinner(peerCertHash)
	tlsCfg.NextProtos = []string{"hermod-p2p"}

	transport := &quic.Transport{
		Conn: &muxedConn{mux: mux},
	}
	conn, err := transport.Dial(ctx, peerAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}
	return conn, nil
}

// ListenQUIC starts a QUIC listener on the muxed conn.
func ListenQUIC(mux *packetMux, cert tls.Certificate, baseTLS *tls.Config, peerCertHash string) (*quic.Listener, error) {
	tlsCfg := baseTLS.Clone()
	tlsCfg.Certificates = []tls.Certificate{cert}
	tlsCfg.ClientAuth = tls.RequireAnyClientCert
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.VerifyPeerCertificate = makeCertPinner(peerCertHash)
	tlsCfg.NextProtos = []string{"hermod-p2p"}

	transport := &quic.Transport{
		Conn: &muxedConn{mux: mux},
	}
	ln, err := transport.Listen(tlsCfg, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("QUIC listen: %w", err)
	}
	return ln, nil
}

// HolePunchDual performs two-phase NAT hole punching: IPv6 first (preferred),
// then IPv4 (fallback). Each phase uses the existing HolePunch function.
//
// The v6 phase has a 5-second timeout. If it succeeds, the v4 phase is skipped.
// If the v6 phase times out or no v6 candidates exist, the v4 phase runs with
// the remaining context timeout.
//
// Pass an empty candidatesV4 or candidatesV6 slice to skip that phase entirely
// (used when -4 or -6 flag enforces a single protocol).
//
// probeCtx controls the probe-sending goroutine's lifetime. See HolePunch
// for details. Pass ctx to use the same lifetime for both.
func HolePunchDual(ctx context.Context, probeCtx context.Context, mux *packetMux, candidatesV4, candidatesV6 []*net.UDPAddr, probeNonce [32]byte) (*HolePunchResult, error) {
	if probeCtx == nil {
		probeCtx = ctx
	}

	// Phase 1: IPv6 (preferred) — 5-second timeout.
	if len(candidatesV6) > 0 {
		v6Ctx, v6Cancel := context.WithTimeout(ctx, 5*time.Second)
		defer v6Cancel()
		result, err := HolePunch(v6Ctx, probeCtx, mux, candidatesV6, probeNonce)
		if err == nil {
			return result, nil
		}
	}

	// Phase 2: IPv4 (fallback) — use remaining context timeout.
	if len(candidatesV4) > 0 {
		result, err := HolePunch(ctx, probeCtx, mux, candidatesV4, probeNonce)
		if err != nil {
			return nil, fmt.Errorf("UDP hole punch failed for all candidates: %w", err)
		}
		return result, nil
	}

	return nil, fmt.Errorf("UDP hole punch failed: no candidates available")
}

// makeCertPinner returns a VerifyPeerCertificate function that enforces cert hash pinning.
// The fingerprint comparison uses crypto/subtle.ConstantTimeCompare to prevent
// timing side-channel attacks (H-01).
func makeCertPinner(expectedHex string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("peer did not present a TLS certificate")
		}
		sum := sha256.Sum256(rawCerts[0])
		got := hex.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(expectedHex)) != 1 {
			return fmt.Errorf("certificate fingerprint mismatch: got %s, expected %s", got, expectedHex)
		}
		return nil
	}
}

// CertFingerprint computes the SHA-256 fingerprint of a DER certificate.
func CertFingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}
