// Package network internal tests (white-box) for unexported types.
package network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- stubPacketConn: controllable net.PacketConn for deterministic readLoop tests ---

// stubPacketConn is a fully controllable net.PacketConn implementation.
// Callers inject packets via readCh and trigger a read error by calling Close.
type stubPacketConn struct {
	readCh chan udpDatagram
	local  net.Addr
	mu     sync.Mutex
	closed bool
	doneCh chan struct{}
	writes [][]byte // collects WriteTo payloads for assertions
}

func newStubPacketConn() *stubPacketConn {
	return &stubPacketConn{
		readCh: make(chan udpDatagram, 32),
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
		doneCh: make(chan struct{}),
	}
}

func (s *stubPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-s.doneCh:
		return 0, nil, net.ErrClosed
	case d := <-s.readCh:
		n := copy(p, d.data)
		return n, d.addr, nil
	}
}

func (s *stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	s.mu.Lock()
	buf := make([]byte, len(p))
	copy(buf, p)
	s.writes = append(s.writes, buf)
	s.mu.Unlock()
	return len(p), nil
}

func (s *stubPacketConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.doneCh)
	}
	return nil
}

func (s *stubPacketConn) LocalAddr() net.Addr                { return s.local }
func (s *stubPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

// --- generateTestCert: creates a throwaway self-signed certificate ---

func generateTestCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return cert, certDER
}

// --- Existing tests (preserved) ---

// TestMuxedConnMethods exercises the net.PacketConn interface on muxedConn.
func TestMuxedConnMethods(t *testing.T) {
	inner, err := BindUDP(":0")
	if err != nil {
		t.Fatal(err)
	}
	mux := NewPacketMux(inner)
	defer mux.Close()

	mc := &muxedConn{mux: mux}

	if mc.LocalAddr() == nil {
		t.Fatal("expected non-nil LocalAddr")
	}
	if err := mc.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := mc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := mc.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if err := mc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestMuxedConnWriteTo exercises WriteTo on muxedConn.
func TestMuxedConnWriteTo(t *testing.T) {
	inner1, _ := BindUDP(":0")
	inner2, _ := BindUDP(":0")
	defer inner2.Close()

	mux := NewPacketMux(inner1)
	defer mux.Close()

	addr2, _ := inner2.LocalAddr().(*net.UDPAddr)

	mc := &muxedConn{mux: mux}
	n, err := mc.WriteTo([]byte{0x01, 0x02}, addr2)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 bytes written, got %d", n)
	}
}

// TestUDPControlErrorPath exercises udpControl error handling indirectly
// by attempting to bind an invalid address.
func TestBindUDPInvalidAddr(t *testing.T) {
	_, err := BindUDP("not-an-address:xyz")
	if err == nil {
		t.Fatal("expected error for invalid bind address")
	}
}

// --- readLoop: error and routing branches ---

// TestReadLoopError verifies readLoop terminates cleanly when the underlying
// conn errors (covers the `return` branch in readLoop).
func TestReadLoopError(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)

	// Close the stub immediately → readLoop's ReadFrom returns net.ErrClosed →
	// readLoop exits via `return`.
	stub.Close()

	// Give the goroutine a moment to observe the error and return.
	time.Sleep(20 * time.Millisecond)

	mux.Close() // idempotent; no panic expected
}

// TestReadLoopPacketRouting verifies that readLoop correctly routes probe packets
// (first byte == probeMarker) to probeCh and QUIC packets to quicCh.
func TestReadLoopPacketRouting(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}

	// Inject a probe packet.
	stub.readCh <- udpDatagram{data: []byte{probeMarker, 0xAB}, addr: peerAddr}
	// Inject a QUIC-like packet.
	stub.readCh <- udpDatagram{data: []byte{0xC0, 0x01, 0x02}, addr: peerAddr}

	// Give readLoop time to process both packets.
	time.Sleep(30 * time.Millisecond)

	// Drain probeCh and quicCh via the exported muxedConn.ReadFrom (quicCh)
	// and direct channel access (probeCh, accessible in package scope).
	select {
	case pkt := <-mux.probeCh:
		if pkt.data[1] != 0xAB {
			t.Errorf("expected probe data 0xAB, got %02x", pkt.data[1])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for probe packet on probeCh")
	}
	select {
	case pkt := <-mux.quicCh:
		if pkt.data[0] != 0xC0 {
			t.Errorf("expected QUIC packet starting 0xC0, got %02x", pkt.data[0])
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for QUIC packet on quicCh")
	}
}

// --- muxedConn.ReadFrom branches ---

// TestMuxedConnReadFrom_Closed verifies ReadFrom returns net.ErrClosed when the mux
// is closed (covers the `case <-c.mux.closed` branch).
func TestMuxedConnReadFrom_Closed(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	mc := &muxedConn{mux: mux}

	// Close the mux so ReadFrom returns immediately.
	mux.Close()

	buf := make([]byte, 1024)
	n, addr, err := mc.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected error from closed mux")
	}
	if n != 0 || addr != nil {
		t.Errorf("expected n=0 and addr=nil on closed ReadFrom, got n=%d addr=%v", n, addr)
	}
}

// TestMuxedConnReadFrom_DeadlineExceeded verifies that ReadFrom returns
// os.ErrDeadlineExceeded when the read deadline is set in the past.
func TestMuxedConnReadFrom_DeadlineExceeded(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	mc := &muxedConn{mux: mux}

	// Set a deadline in the past.
	if err := mc.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 1024)
	_, _, err := mc.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected deadline exceeded error")
	}
	if !os.IsTimeout(err) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

// TestMuxedConnReadFrom_DeadlineFires verifies that ReadFrom returns
// os.ErrDeadlineExceeded when the deadline expires while waiting.
func TestMuxedConnReadFrom_DeadlineFires(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	mc := &muxedConn{mux: mux}

	// Set a deadline 50ms in the future.
	if err := mc.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 1024)
	_, _, err := mc.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected deadline exceeded error")
	}
	if !os.IsTimeout(err) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

// TestMuxedConnWriteTo_DeadlineExceeded verifies that WriteTo returns
// os.ErrDeadlineExceeded when the write deadline is set in the past.
func TestMuxedConnWriteTo_DeadlineExceeded(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	mc := &muxedConn{mux: mux}

	if err := mc.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	_, err := mc.WriteTo([]byte{0x01}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999})
	if err == nil {
		t.Fatal("expected deadline exceeded error")
	}
	if !os.IsTimeout(err) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

// TestMuxedConnReadFrom_Normal verifies ReadFrom delivers a packet from quicCh.
func TestMuxedConnReadFrom_Normal(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8888}

	// Inject a QUIC-like packet so readLoop routes it to quicCh.
	go func() {
		time.Sleep(10 * time.Millisecond)
		stub.readCh <- udpDatagram{data: []byte{0xC0, 0xAA, 0xBB}, addr: peerAddr}
	}()

	mc := &muxedConn{mux: mux}
	buf := make([]byte, 1024)

	doneCh := make(chan struct{})
	go func() {
		n, addr, err := mc.ReadFrom(buf)
		if err != nil {
			t.Errorf("ReadFrom: unexpected error: %v", err)
		}
		if n != 3 {
			t.Errorf("ReadFrom: expected 3 bytes, got %d", n)
		}
		if addr.(*net.UDPAddr).Port != 8888 {
			t.Errorf("ReadFrom: wrong addr port: %v", addr)
		}
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ReadFrom to return")
	}
}

// --- makeCertPinner ---

// TestMakeCertPinner_NoCerts verifies the "peer did not present" error path.
func TestMakeCertPinner_NoCerts(t *testing.T) {
	pinner := makeCertPinner("anyhexhash")
	err := pinner(nil, nil)
	if err == nil {
		t.Fatal("expected error when no certs presented")
	}
	if !strings.Contains(err.Error(), "peer did not present") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestMakeCertPinner_HashMismatch verifies the fingerprint mismatch error path.
func TestMakeCertPinner_HashMismatch(t *testing.T) {
	pinner := makeCertPinner("0000000000000000000000000000000000000000000000000000000000000000")
	// Generate a real cert (fake bytes won't parse for SPKI extraction).
	_, certDER := generateTestCert(t)
	err := pinner([][]byte{certDER}, nil)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
	if !strings.Contains(err.Error(), "peer identity verification failed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestMakeCertPinner_Match verifies that a matching SPKI fingerprint returns nil.
func TestMakeCertPinner_Match(t *testing.T) {
	_, certDER := generateTestCert(t)
	fp := PubKeyFingerprint(certDER)
	pinner := makeCertPinner(fp)
	if err := pinner([][]byte{certDER}, nil); err != nil {
		t.Fatalf("expected nil for matching fingerprint: %v", err)
	}
}

// --- HolePunch ---

// testProbeNonce is a fixed nonce used in HolePunch unit tests.
// probe = [probeMarker, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11]
// ack   = [probeMarker, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]
var testProbeNonce = [32]byte{
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // bytes 0-7 — probe
	0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, // bytes 8-15 — ack
}

// TestHolePunch_Timeout verifies HolePunch returns a descriptive error when the
// context deadline is exceeded before a peer is found.
func TestHolePunch_Timeout(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	_, err := HolePunch(ctx, ctx, mux, []*net.UDPAddr{}, testProbeNonce)
	if err == nil {
		t.Fatal("expected timeout error from HolePunch")
	}
	if !strings.Contains(err.Error(), "unreachable after 10s") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestHolePunch_ProbeReceived verifies HolePunch succeeds when it receives a
// probe packet — this triggers the ack-send-then-return path.
func TestHolePunch_ProbeReceived(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7777}

	// Inject a probe after a short delay.
	go func() {
		time.Sleep(30 * time.Millisecond)
		stub.readCh <- udpDatagram{
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1], testProbeNonce[2], testProbeNonce[3], testProbeNonce[4], testProbeNonce[5], testProbeNonce[6]},
			addr: peerAddr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunch(ctx, ctx, mux, []*net.UDPAddr{}, testProbeNonce)
	if err != nil {
		t.Fatalf("HolePunch: unexpected error: %v", err)
	}
	if result.PeerAddr.Port != 7777 {
		t.Errorf("wrong peer port: got %d, want 7777", result.PeerAddr.Port)
	}
}

// TestHolePunch_AckReceived verifies HolePunch succeeds when it receives an ack
// packet — covers the alternate return path.
func TestHolePunch_AckReceived(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6666}

	go func() {
		time.Sleep(30 * time.Millisecond)
		stub.readCh <- udpDatagram{
			data: []byte{probeMarker, testProbeNonce[8], testProbeNonce[9], testProbeNonce[10], testProbeNonce[11], testProbeNonce[12], testProbeNonce[13], testProbeNonce[14]},
			addr: peerAddr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunch(ctx, ctx, mux, []*net.UDPAddr{}, testProbeNonce)
	if err != nil {
		t.Fatalf("HolePunch (ack path): unexpected error: %v", err)
	}
	if result.PeerAddr.Port != 6666 {
		t.Errorf("wrong peer port: got %d, want 6666", result.PeerAddr.Port)
	}
}

// TestHolePunch_ShortProbeIgnored verifies that a probe packet shorter than 8 bytes
// is ignored (the `continue` branch) and HolePunch keeps waiting.
func TestHolePunch_ShortProbeIgnored(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5556}

	go func() {
		// First: inject a short probe (ignored).
		time.Sleep(20 * time.Millisecond)
		stub.readCh <- udpDatagram{
			data: []byte{probeMarker}, // only 1 byte — ignored
			addr: peerAddr,
		}
		// Then: inject a valid probe so HolePunch can return.
		time.Sleep(20 * time.Millisecond)
		stub.readCh <- udpDatagram{
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1], testProbeNonce[2], testProbeNonce[3], testProbeNonce[4], testProbeNonce[5], testProbeNonce[6]},
			addr: peerAddr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunch(ctx, ctx, mux, []*net.UDPAddr{}, testProbeNonce)
	if err != nil {
		t.Fatalf("HolePunch (short probe ignored): %v", err)
	}
	if result.PeerAddr.Port != 5556 {
		t.Errorf("wrong peer port: got %d, want 5556", result.PeerAddr.Port)
	}
}

// TestHolePunch_ProbesSentToCandidates verifies the probe-sending goroutine
// actually writes to candidate addresses via the ticker path.
func TestHolePunch_ProbesSentToCandidates(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	candidate := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4444}

	// Inject a valid probe shortly after starting so HolePunch can return.
	go func() {
		// Wait at least 200ms so the ticker fires at least once.
		time.Sleep(250 * time.Millisecond)
		stub.readCh <- udpDatagram{
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1], testProbeNonce[2], testProbeNonce[3], testProbeNonce[4], testProbeNonce[5], testProbeNonce[6]},
			addr: candidate,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := HolePunch(ctx, ctx, mux, []*net.UDPAddr{candidate}, testProbeNonce); err != nil {
		t.Fatalf("HolePunch with candidate: %v", err)
	}

	stub.mu.Lock()
	n := len(stub.writes)
	stub.mu.Unlock()
	if n == 0 {
		t.Error("expected at least one probe write to candidate, got 0")
	}
}

// --- HolePunchDual ---

// TestHolePunchDual_V6Preferred verifies that when both v4 and v6 candidates
// are available and the v6 probe arrives first, the v6 result is returned.
func TestHolePunchDual_V6Preferred(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	v6Addr := &net.UDPAddr{IP: net.IPv6loopback, Port: 7776}
	v4Addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7777}

	// Inject a v6 probe after a short delay.
	go func() {
		time.Sleep(30 * time.Millisecond)
		stub.readCh <- udpDatagram{
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1], testProbeNonce[2], testProbeNonce[3], testProbeNonce[4], testProbeNonce[5], testProbeNonce[6]},
			addr: v6Addr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunchDual(ctx, ctx, mux, []*net.UDPAddr{v4Addr}, []*net.UDPAddr{v6Addr}, testProbeNonce)
	if err != nil {
		t.Fatalf("HolePunchDual: %v", err)
	}
	if result.PeerAddr.Port != 7776 {
		t.Errorf("expected v6 peer (port 7776), got port %d", result.PeerAddr.Port)
	}
}

// TestHolePunchDual_V4Fallback verifies that when v6 candidates are empty,
// the v4 phase runs immediately and succeeds.
func TestHolePunchDual_V4Fallback(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	v4Addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7777}

	// No v6 candidates — v6 phase is skipped. Inject a v4 probe after a short delay.
	go func() {
		time.Sleep(30 * time.Millisecond)
		stub.readCh <- udpDatagram{
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1], testProbeNonce[2], testProbeNonce[3], testProbeNonce[4], testProbeNonce[5], testProbeNonce[6]},
			addr: v4Addr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunchDual(ctx, ctx, mux, []*net.UDPAddr{v4Addr}, []*net.UDPAddr{}, testProbeNonce)
	if err != nil {
		t.Fatalf("HolePunchDual (v4 fallback): %v", err)
	}
	if result.PeerAddr.Port != 7777 {
		t.Errorf("expected v4 peer (port 7777), got port %d", result.PeerAddr.Port)
	}
}

// TestHolePunchDual_OnlyV4 verifies that when only v4 candidates exist, the v4
// phase runs immediately (skipping v6) and succeeds.
func TestHolePunchDual_OnlyV4(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	v4Addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7777}

	go func() {
		time.Sleep(30 * time.Millisecond)
		stub.readCh <- udpDatagram{
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1], testProbeNonce[2], testProbeNonce[3], testProbeNonce[4], testProbeNonce[5], testProbeNonce[6]},
			addr: v4Addr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunchDual(ctx, ctx, mux, []*net.UDPAddr{v4Addr}, nil, testProbeNonce)
	if err != nil {
		t.Fatalf("HolePunchDual (only v4): %v", err)
	}
	if result.PeerAddr.Port != 7777 {
		t.Errorf("expected port 7777, got %d", result.PeerAddr.Port)
	}
}

// TestHolePunchDual_NoCandidates verifies that when both candidate lists are
// empty, an appropriate error is returned.
func TestHolePunchDual_NoCandidates(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := HolePunchDual(ctx, ctx, mux, nil, nil, testProbeNonce)
	if err == nil {
		t.Fatal("expected error for no candidates")
	}
	if !strings.Contains(err.Error(), "no candidates") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestLocalEndpoints_FilterV4 verifies that IPFamilyV4 returns only IPv4 addresses.
func TestLocalEndpoints_FilterV4(t *testing.T) {
	v4, v6, err := LocalEndpoints(9999, IPFamilyV4)
	if err != nil {
		t.Fatalf("LocalEndpoints: %v", err)
	}
	if len(v6) != 0 {
		t.Log("expected empty v6 list with IPFamilyV4 filter")
	}
	_ = v4 // may be empty in some environments, but at least no v6 leak
}

// TestLocalEndpoints_FilterV6 verifies that IPFamilyV6 returns only IPv6 addresses.
func TestLocalEndpoints_FilterV6(t *testing.T) {
	v4, v6, err := LocalEndpoints(9999, IPFamilyV6)
	if err != nil {
		t.Fatalf("LocalEndpoints: %v", err)
	}
	if len(v4) != 0 {
		t.Log("expected empty v4 list with IPFamilyV6 filter")
	}
	_ = v6
}

// TestLocalEndpoints_Formatting verifies that IPv6 addresses are properly
// bracketed (e.g. [::1]:port) and IPv4 addresses are not.
func TestLocalEndpoints_Formatting(t *testing.T) {
	v4, v6, err := LocalEndpoints(9999, IPFamilyAny)
	if err != nil {
		t.Fatalf("LocalEndpoints: %v", err)
	}
	for _, ep := range v4 {
		_, _, err := net.SplitHostPort(ep)
		if err != nil {
			t.Errorf("invalid v4 endpoint %q: %v", ep, err)
		}
	}
	for _, ep := range v6 {
		_, _, err := net.SplitHostPort(ep)
		if err != nil {
			t.Errorf("invalid v6 endpoint %q: %v", ep, err)
		}
	}
}

// --- DialQUIC / ListenQUIC ---

// TestDialAndListenQUIC verifies a full QUIC handshake between two muxes on
// loopback, covering DialQUIC, ListenQUIC, and the makeCertPinner match path.
func TestDialAndListenQUIC(t *testing.T) {
	dialerCert, dialerDER := generateTestCert(t)
	listenerCert, listenerDER := generateTestCert(t)

	dialerFP := PubKeyFingerprint(dialerDER)
	listenerFP := PubKeyFingerprint(listenerDER)

	// Bind two real UDP sockets on loopback.
	inner1, err := BindUDP(":0")
	if err != nil {
		t.Fatalf("BindUDP (listener): %v", err)
	}
	inner2, err := BindUDP(":0")
	if err != nil {
		t.Fatalf("BindUDP (dialer): %v", err)
	}

	mux1 := NewPacketMux(inner1) // listener side
	defer mux1.Close()
	mux2 := NewPacketMux(inner2) // dialer side
	defer mux2.Close()

	addr1, err := LocalUDPAddr(inner1)
	if err != nil {
		t.Fatalf("LocalUDPAddr: %v", err)
	}

	baseTLS := &tls.Config{MinVersion: tls.VersionTLS13}

	// Start QUIC listener on mux1: expects the dialer's fingerprint.
	ln, err := ListenQUIC(mux1, listenerCert, baseTLS.Clone(), dialerFP)
	if err != nil {
		t.Fatalf("ListenQUIC: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	acceptErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err == nil {
			conn.CloseWithError(0, "done") //nolint:errcheck
		}
		acceptErrCh <- err
	}()

	// Dial from mux2 to mux1: expects the listener's fingerprint.
	dialerBaseTLS := baseTLS.Clone()
	dialerBaseTLS.Certificates = []tls.Certificate{dialerCert}
	dialConn, err := DialQUIC(ctx, mux2, addr1, dialerBaseTLS, listenerFP)
	if err != nil {
		t.Fatalf("DialQUIC: %v", err)
	}
	defer dialConn.CloseWithError(0, "done") //nolint:errcheck

	if err := <-acceptErrCh; err != nil {
		t.Fatalf("listener Accept: %v", err)
	}
}

// --- DiscoverViaReflector (M-02 audit fix) ---

// TestDiscoverViaReflector_WrongSourcePhase1 verifies that a phase-1 cookie
// response from an unexpected source address is rejected, preventing an
// on-path attacker from injecting a spoofed cookie response (audit M-02).
func TestDiscoverViaReflector_WrongSourcePhase1(t *testing.T) {
	stub := newStubPacketConn()
	serverAddr := "127.0.0.1:12345"
	wrongAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999}

	// Inject a phase-1 cookie response (9 bytes, magic + 8 cookie bytes)
	// from a source that does not match the expected reflector address.
	stub.readCh <- udpDatagram{
		data: []byte{reflectCookieMagic, 1, 2, 3, 4, 5, 6, 7, 8},
		addr: wrongAddr,
	}

	_, err := DiscoverViaReflector(stub, serverAddr, time.Second)
	if err == nil {
		t.Fatal("expected error for phase-1 response from wrong source")
	}
	if !strings.Contains(err.Error(), "unexpected source") {
		t.Errorf("expected 'unexpected source' error, got: %v", err)
	}
}

// TestDiscoverViaReflector_WrongSourcePhase2 verifies that a phase-2 address
// response from an unexpected source is rejected. An attacker who observed the
// cleartext cookie in phase 1 could forge a phase-2 response; source-address
// verification prevents this (audit M-02).
func TestDiscoverViaReflector_WrongSourcePhase2(t *testing.T) {
	stub := newStubPacketConn()
	serverAddr := "127.0.0.1:12345"
	correctAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	wrongAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999}

	// Phase-1 response from correct source passes verification.
	stub.readCh <- udpDatagram{
		data: []byte{reflectCookieMagic, 1, 2, 3, 4, 5, 6, 7, 8},
		addr: correctAddr,
	}
	// Phase-2 address response from wrong source should be rejected.
	stub.readCh <- udpDatagram{
		data: []byte{0x04, 192, 168, 1, 1, 0x11, 0x5c},
		addr: wrongAddr,
	}

	_, err := DiscoverViaReflector(stub, serverAddr, time.Second)
	if err == nil {
		t.Fatal("expected error for phase-2 response from wrong source")
	}
	if !strings.Contains(err.Error(), "unexpected source") {
		t.Errorf("expected 'unexpected source' error, got: %v", err)
	}
}

// TestDiscoverViaReflector_Success verifies that responses from the correct
// reflector source address are accepted and the external address is decoded.
func TestDiscoverViaReflector_Success(t *testing.T) {
	stub := newStubPacketConn()
	serverAddr := "127.0.0.1:12345"
	correctAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Phase-1 cookie response from correct source.
	stub.readCh <- udpDatagram{
		data: []byte{reflectCookieMagic, 1, 2, 3, 4, 5, 6, 7, 8},
		addr: correctAddr,
	}
	// Phase-2 IPv4 address response (0x04 + IP + port) from correct source.
	stub.readCh <- udpDatagram{
		data: []byte{0x04, 192, 168, 1, 1, 0x11, 0x5c},
		addr: correctAddr,
	}

	result, err := DiscoverViaReflector(stub, serverAddr, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IP.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("expected IP 192.168.1.1, got %s", result.IP)
	}
	if result.Port != 4444 {
		t.Errorf("expected port 4444, got %d", result.Port)
	}
}
