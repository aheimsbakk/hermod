// Package network implements UDP multiplexing, NAT hole punching, and QUIC transport.
package network

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
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
	mux *packetMux
}

func (c *muxedConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.mux.closed:
		return 0, nil, net.ErrClosed
	case pkt, ok := <-c.mux.quicCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n = copy(p, pkt.data)
		return n, pkt.addr, nil
	}
}

func (c *muxedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.mux.conn.WriteTo(p, addr)
}

func (c *muxedConn) Close() error                       { return nil } // managed by mux
func (c *muxedConn) LocalAddr() net.Addr                { return c.mux.conn.LocalAddr() }
func (c *muxedConn) SetDeadline(t time.Time) error      { return nil }
func (c *muxedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *muxedConn) SetWriteDeadline(t time.Time) error { return nil }

// BindUDP binds a UDP socket on the given address (":0" for OS-assigned port).
// SO_REUSEADDR/SO_REUSEPORT are set via udpControl (platform-specific file).
func BindUDP(addr string) (net.PacketConn, error) {
	lc := &net.ListenConfig{
		Control: udpControl,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind udp %s: %w", addr, err)
	}
	return conn, nil
}

// LocalUDPAddr returns the local endpoint as a *net.UDPAddr.
func LocalUDPAddr(conn net.PacketConn) (*net.UDPAddr, error) {
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("not a UDP connection")
	}
	return addr, nil
}

// HolePunchResult carries the outcome of NAT hole punching.
type HolePunchResult struct {
	PeerAddr *net.UDPAddr
}

// HolePunch performs simultaneous UDP hole punching to each candidate address.
// probeNonce is a 4-byte session-unique value derived by the caller (e.g.
// SHA-256(kClassical)[:4]). The probe and ack payloads are derived from it,
// making them unguessable to an off-path attacker and preventing spoofed
// ack injection (L-07).
// Returns as soon as a probe/ack exchange succeeds or ctx is cancelled.
func HolePunch(ctx context.Context, mux *packetMux, candidates []*net.UDPAddr, probeNonce [4]byte) (*HolePunchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// probe = [probeMarker, nonce[0], nonce[1]]
	// ack   = [probeMarker, nonce[2], nonce[3]]
	probe := []byte{probeMarker, probeNonce[0], probeNonce[1]}
	ack := []byte{probeMarker, probeNonce[2], probeNonce[3]}

	// Send probes to all candidates periodically
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
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
			return nil, fmt.Errorf("hole punch timed out: %w", ctx.Err())
		case pkt := <-mux.probeCh:
			if len(pkt.data) < 3 {
				continue
			}
			switch {
			case pkt.data[1] == probeNonce[0] && pkt.data[2] == probeNonce[1]: // received probe — send ack
				mux.conn.WriteTo(ack, pkt.addr) //nolint:errcheck
				if udpAddr, ok := pkt.addr.(*net.UDPAddr); ok {
					return &HolePunchResult{PeerAddr: udpAddr}, nil
				}
			case pkt.data[1] == probeNonce[2] && pkt.data[2] == probeNonce[3]: // received ack
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
		return nil, fmt.Errorf("quic dial: %w", err)
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
		return nil, fmt.Errorf("quic listen: %w", err)
	}
	return ln, nil
}

// makeCertPinner returns a VerifyPeerCertificate function that enforces cert hash pinning.
func makeCertPinner(expectedHex string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no peer certificate presented")
		}
		sum := sha256.Sum256(rawCerts[0])
		got := hex.EncodeToString(sum[:])
		if got != expectedHex {
			return fmt.Errorf("cert fingerprint mismatch: got %s, want %s", got, expectedHex)
		}
		return nil
	}
}

// CertFingerprint computes the SHA-256 fingerprint of a DER certificate.
func CertFingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}
