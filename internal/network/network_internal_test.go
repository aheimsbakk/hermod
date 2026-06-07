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
// os.ErrDeadlineExceeded when the read deadline is set in the past (H-02).
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
// os.ErrDeadlineExceeded when the deadline expires while waiting (H-02).
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
// os.ErrDeadlineExceeded when the write deadline is set in the past (H-02).
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

// TestMakeCertPinner_NoCerts verifies the "no peer certificate" error path.
func TestMakeCertPinner_NoCerts(t *testing.T) {
	pinner := makeCertPinner("anyhexhash")
	err := pinner(nil, nil)
	if err == nil {
		t.Fatal("expected error when no certs presented")
	}
	if !strings.Contains(err.Error(), "no peer certificate") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestMakeCertPinner_HashMismatch verifies the fingerprint mismatch error path.
func TestMakeCertPinner_HashMismatch(t *testing.T) {
	pinner := makeCertPinner("0000000000000000000000000000000000000000000000000000000000000000")
	fakeCert := make([]byte, 64) // sha256 won't match the zero hex
	for i := range fakeCert {
		fakeCert[i] = 0xFF
	}
	err := pinner([][]byte{fakeCert}, nil)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
	if !strings.Contains(err.Error(), "cert fingerprint mismatch") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestMakeCertPinner_Match verifies that a matching fingerprint returns nil.
func TestMakeCertPinner_Match(t *testing.T) {
	_, certDER := generateTestCert(t)
	fp := CertFingerprint(certDER)
	pinner := makeCertPinner(fp)
	if err := pinner([][]byte{certDER}, nil); err != nil {
		t.Fatalf("expected nil for matching fingerprint: %v", err)
	}
}

// --- HolePunch ---

// testProbeNonce is a fixed nonce used in HolePunch unit tests (L-07).
// probe = [probeMarker, 0xAA, 0xBB], ack = [probeMarker, 0xCC, 0xDD].
var testProbeNonce = [4]byte{0xAA, 0xBB, 0xCC, 0xDD}

// TestHolePunch_Timeout verifies HolePunch returns a descriptive error when the
// context deadline is exceeded before a peer is found.
func TestHolePunch_Timeout(t *testing.T) {
	stub := newStubPacketConn()
	mux := NewPacketMux(stub)
	defer mux.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	_, err := HolePunch(ctx, mux, []*net.UDPAddr{}, testProbeNonce)
	if err == nil {
		t.Fatal("expected timeout error from HolePunch")
	}
	if !strings.Contains(err.Error(), "hole punch timed out") {
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
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1]},
			addr: peerAddr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunch(ctx, mux, []*net.UDPAddr{}, testProbeNonce)
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
			data: []byte{probeMarker, testProbeNonce[2], testProbeNonce[3]},
			addr: peerAddr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunch(ctx, mux, []*net.UDPAddr{}, testProbeNonce)
	if err != nil {
		t.Fatalf("HolePunch (ack path): unexpected error: %v", err)
	}
	if result.PeerAddr.Port != 6666 {
		t.Errorf("wrong peer port: got %d, want 6666", result.PeerAddr.Port)
	}
}

// TestHolePunch_ShortProbeIgnored verifies that a probe packet shorter than 3 bytes
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
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1]},
			addr: peerAddr,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := HolePunch(ctx, mux, []*net.UDPAddr{}, testProbeNonce)
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
			data: []byte{probeMarker, testProbeNonce[0], testProbeNonce[1]},
			addr: candidate,
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := HolePunch(ctx, mux, []*net.UDPAddr{candidate}, testProbeNonce); err != nil {
		t.Fatalf("HolePunch with candidate: %v", err)
	}

	stub.mu.Lock()
	n := len(stub.writes)
	stub.mu.Unlock()
	if n == 0 {
		t.Error("expected at least one probe write to candidate, got 0")
	}
}

// --- DialQUIC / ListenQUIC ---

// TestDialAndListenQUIC verifies a full QUIC handshake between two muxes on
// loopback, covering DialQUIC, ListenQUIC, and the makeCertPinner match path.
func TestDialAndListenQUIC(t *testing.T) {
	dialerCert, dialerDER := generateTestCert(t)
	listenerCert, listenerDER := generateTestCert(t)

	dialerFP := CertFingerprint(dialerDER)
	listenerFP := CertFingerprint(listenerDER)

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
