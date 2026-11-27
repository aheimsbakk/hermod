// Single-UDP-socket demultiplexer: routes hole-punch probes and
// QUIC datagrams by first byte, and adapts the QUIC channel to net.PacketConn.

package network

import (
	"net"
	"os"
	"sync"
	"time"
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

// --- Packet mux constants ---

// packetMuxQuicChCap is the capacity of the channel that carries QUIC datagrams
// from the readLoop to consumers. Sized for 10 Gbit/s throughput: at line rate
// a ~1.5 KB datagram arrives every ~1.2 µs, so 16 384 slots absorb bursts
// for ~20 ms without dropping packets.
const packetMuxQuicChCap = 16384

// packetMuxProbeChCap is the capacity of the channel that carries probe packets
// (NAT hole-punch markers) from the readLoop. Probe traffic is negligible
// compared to QUIC data, so the smaller capacity is sufficient.
const packetMuxProbeChCap = 64

// packetMuxReadBuf is the size of the per-read buffer in the readLoop.
// Sized to absorb burst traffic without wasting memory on small per-read copies.
// 1 MiB absorbs a ~700-packet burst on a 10 Gbit/s link.
const packetMuxReadBuf = 1 << 20 // 1 MiB

// NewPacketMux wraps a PacketConn and starts the demux loop.
func NewPacketMux(conn net.PacketConn) *packetMux {
	m := &packetMux{
		conn:    conn,
		quicCh:  make(chan udpDatagram, packetMuxQuicChCap),
		probeCh: make(chan udpDatagram, packetMuxProbeChCap),
		closed:  make(chan struct{}),
	}
	go m.readLoop()
	return m
}

func (m *packetMux) readLoop() {
	buf := make([]byte, packetMuxReadBuf)
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

// quic-go checks for these interfaces to increase UDP socket buffers.
// Without them it logs a harmless warning and uses the OS default size.
// We delegate to the underlying socket; if the underlying conn does not
// support them (e.g. in tests), this is a no-op.
type udpSetReadBuffer interface {
	SetReadBuffer(int) error
}
type udpSetSendBuffer interface {
	SetSendBuffer(int) error
}
type udpSetWriteBuffer interface {
	SetWriteBuffer(int) error
}

func (c *muxedConn) SetReadBuffer(n int) error {
	if sb, ok := c.mux.conn.(udpSetReadBuffer); ok {
		return sb.SetReadBuffer(n)
	}
	return nil
}

func (c *muxedConn) SetSendBuffer(n int) error {
	if sb, ok := c.mux.conn.(udpSetSendBuffer); ok {
		return sb.SetSendBuffer(n)
	}
	return nil
}

func (c *muxedConn) SetWriteBuffer(n int) error {
	if sb, ok := c.mux.conn.(udpSetWriteBuffer); ok {
		return sb.SetWriteBuffer(n)
	}
	return nil
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
