package network_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hermod/hermod/internal/network"
)

func TestLocalEndpoints(t *testing.T) {
	v4, v6, err := network.LocalEndpoints(12345, network.IPFamilyAny)
	if err != nil {
		t.Fatalf("local endpoints: %v", err)
	}
	// May be empty in some environments, but should not error
	for _, ep := range v4 {
		_, _, err := net.SplitHostPort(ep)
		if err != nil {
			t.Fatalf("invalid v4 endpoint %q: %v", ep, err)
		}
	}
	for _, ep := range v6 {
		_, _, err := net.SplitHostPort(ep)
		if err != nil {
			t.Fatalf("invalid v6 endpoint %q: %v", ep, err)
		}
	}
}

func TestEncodeDecodeEndpointBundle(t *testing.T) {
	bundle := network.EndpointBundle{
		LocalEndpointsV4:  []string{"192.168.1.1:4376", "10.0.0.1:4376"},
		PublicEndpointV4:  "1.2.3.4:4376",
		PubKeyFingerprint: "aabbccdd",
	}
	data, err := network.EncodeEndpointBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := network.DecodeEndpointBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PublicEndpointV4 != bundle.PublicEndpointV4 {
		t.Fatalf("public endpoint mismatch")
	}
	if decoded.PubKeyFingerprint != bundle.PubKeyFingerprint {
		t.Fatal("fingerprint mismatch")
	}
	if len(decoded.LocalEndpointsV4) != len(bundle.LocalEndpointsV4) {
		t.Fatal("local endpoints count mismatch")
	}
}

func TestParseCandidates(t *testing.T) {
	eps := []string{"192.168.1.1:4376", "1.2.3.4:9000"}
	addrs, err := network.ParseCandidates(eps)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(addrs))
	}
}

func TestParseCandidatesInvalid(t *testing.T) {
	_, err := network.ParseCandidates([]string{"not-valid"})
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestPubKeyFingerprint(t *testing.T) {
	// Generate a real certificate and verify the SPKI fingerprint length.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	got := network.PubKeyFingerprint(certDER)
	if len(got) != 64 {
		t.Fatalf("expected 64-char SPKI fingerprint, got %d", len(got))
	}
	// For the same cert, CertFingerprint (cert DER hash) and PubKeyFingerprint
	// (SPKI hash) must differ because they hash different data.
	certFP := network.CertFingerprint(certDER)
	if got == certFP {
		t.Fatal("SPKI fingerprint must differ from cert fingerprint")
	}
}

func TestPubKeyFingerprint_Invalid(t *testing.T) {
	fp := network.PubKeyFingerprint([]byte("not-a-valid-cert-der"))
	if fp != "" {
		t.Fatalf("expected empty string for invalid DER, got %q", fp)
	}
}

func TestBindUDP(t *testing.T) {
	conn, err := network.BindUDP(":0")
	if err != nil {
		t.Fatalf("bind udp: %v", err)
	}
	defer conn.Close()

	addr, err := network.LocalUDPAddr(conn)
	if err != nil {
		t.Fatalf("local udp addr: %v", err)
	}
	if addr.Port == 0 {
		t.Fatal("expected non-zero port")
	}
}

func TestDecodeEndpointBundleInvalid(t *testing.T) {
	_, err := network.DecodeEndpointBundle([]byte("not json"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestNewPacketMuxClose verifies that closing a mux terminates the readLoop
// and makes the underlying socket available for reuse.
// Packet routing (QUIC vs probe) is exhaustively tested in the internal
// package via TestReadLoopPacketRouting.
func TestNewPacketMuxClose(t *testing.T) {
	conn, err := network.BindUDP(":0")
	if err != nil {
		t.Fatal(err)
	}

	mux := network.NewPacketMux(conn)
	mux.Close()

	// Verify mux.Close is idempotent — no panic.
	mux.Close()

	// The underlying socket should be closed after mux.Close.
	_, _, err = conn.ReadFrom(make([]byte, 64))
	if err == nil {
		t.Error("expected error reading from closed mux socket")
	}
}

// TestPacketMuxMethods covers Close and LocalAddr on the mux.
func TestPacketMuxMethods(t *testing.T) {
	conn, err := network.BindUDP(":0")
	if err != nil {
		t.Fatal(err)
	}
	mux := network.NewPacketMux(conn)

	if mux.LocalAddr() == nil {
		t.Fatal("expected non-nil LocalAddr")
	}
	mux.Close() // void — just ensure no panic
}

// TestEndpointBundleRequireVerify ensures RequireVerify round-trips through JSON.
func TestEndpointBundleRequireVerify(t *testing.T) {
	bundle := network.EndpointBundle{
		LocalEndpointsV4:  []string{"192.168.1.1:4376"},
		PublicEndpointV4:  "1.2.3.4:4376",
		PubKeyFingerprint: "aabbccdd",
		RequireVerify:     true,
	}
	data, err := network.EncodeEndpointBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := network.DecodeEndpointBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.RequireVerify {
		t.Fatal("RequireVerify should be true after round-trip")
	}

	// A bundle without RequireVerify should default to false
	bundleNoVerify := network.EndpointBundle{
		LocalEndpointsV4:  []string{"192.168.1.1:4376"},
		PublicEndpointV4:  "1.2.3.4:4376",
		PubKeyFingerprint: "aabbccdd",
	}
	data2, err := network.EncodeEndpointBundle(bundleNoVerify)
	if err != nil {
		t.Fatal(err)
	}
	decoded2, err := network.DecodeEndpointBundle(data2)
	if err != nil {
		t.Fatal(err)
	}
	if decoded2.RequireVerify {
		t.Fatal("RequireVerify should be false when not set")
	}
}

// --- Dual-stack endpoint tests ---

func TestEndpointBundle_RoundTripDual(t *testing.T) {
	bundle := network.EndpointBundle{
		LocalEndpointsV4:  []string{"192.168.1.1:4376", "10.0.0.1:4376"},
		LocalEndpointsV6:  []string{"[2001:db8::1]:4376", "[fe80::1]:4376"},
		PublicEndpointV4:  "1.2.3.4:4376",
		PublicEndpointV6:  "[2001:db8::1]:4376",
		PubKeyFingerprint: "aabbccdd",
		RequireVerify:     true,
	}
	data, err := network.EncodeEndpointBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := network.DecodeEndpointBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PublicEndpointV4 != "1.2.3.4:4376" {
		t.Fatalf("PublicEndpointV4: got %q", decoded.PublicEndpointV4)
	}
	if decoded.PublicEndpointV6 != "[2001:db8::1]:4376" {
		t.Fatalf("PublicEndpointV6: got %q", decoded.PublicEndpointV6)
	}
	if len(decoded.LocalEndpointsV4) != 2 {
		t.Fatalf("LocalEndpointsV4 count: got %d", len(decoded.LocalEndpointsV4))
	}
	if len(decoded.LocalEndpointsV6) != 2 {
		t.Fatalf("LocalEndpointsV6 count: got %d", len(decoded.LocalEndpointsV6))
	}
	if !decoded.RequireVerify {
		t.Fatal("RequireVerify should be true")
	}
}

func TestSplitPublicIP_V4(t *testing.T) {
	v4, v6 := network.SplitPublicIP("1.2.3.4", "4376")
	if v4 != "1.2.3.4:4376" {
		t.Fatalf("unexpected v4: %q", v4)
	}
	if v6 != "" {
		t.Fatalf("expected empty v6, got %q", v6)
	}
}

func TestSplitPublicIP_V6(t *testing.T) {
	v4, v6 := network.SplitPublicIP("2001:db8::1", "4376")
	if v4 != "" {
		t.Fatalf("expected empty v4, got %q", v4)
	}
	if v6 != "[2001:db8::1]:4376" {
		t.Fatalf("unexpected v6: %q", v6)
	}
}

func TestSplitPublicIP_Empty(t *testing.T) {
	v4, v6 := network.SplitPublicIP("", "4376")
	if v4 != "" || v6 != "" {
		t.Fatalf("expected both empty, got v4=%q v6=%q", v4, v6)
	}
}

func TestSplitPublicIP_Hostname(t *testing.T) {
	// Hostname is not a valid IP — returned as v4.
	v4, v6 := network.SplitPublicIP("example.com", "4376")
	if v4 != "example.com:4376" {
		t.Fatalf("expected hostname in v4, got %q", v4)
	}
	if v6 != "" {
		t.Fatalf("expected empty v6, got %q", v6)
	}
}

func TestSplitPublicIP_V6_ZoneID(t *testing.T) {
	// IPv6 with zone/scope ID — net.ParseIP alone would fail,
	// but SplitPublicIP strips the zone before classifying.
	v4, v6 := network.SplitPublicIP("fe80::1%eth0", "4376")
	if v4 != "" {
		t.Fatalf("expected empty v4, got %q", v4)
	}
	if v6 != "[fe80::1%eth0]:4376" {
		t.Fatalf("unexpected v6: %q", v6)
	}
}

func TestSplitPublicIP_V6_ZoneIDWithPort(t *testing.T) {
	v4, v6 := network.SplitPublicIP("fe80::aabb:ccff:fe01:2345%wlan0", "9000")
	if v4 != "" {
		t.Fatalf("expected empty v4, got %q", v4)
	}
	if v6 != "[fe80::aabb:ccff:fe01:2345%wlan0]:9000" {
		t.Fatalf("unexpected v6: %q", v6)
	}
}

// --- Hybrid KEM blob serialization tests ---

func TestSenderHandshakeBlob_RoundTrip(t *testing.T) {
	cpacePub := make([]byte, network.CPacePointSize)
	x25519Pub := make([]byte, network.X25519PubSize)
	for i := range cpacePub {
		cpacePub[i] = byte(i)
	}
	for i := range x25519Pub {
		x25519Pub[i] = byte(i + 100)
	}

	blob := network.SenderHandshakeBlob(cpacePub, x25519Pub)
	if len(blob) != network.CPacePointSize+network.X25519PubSize {
		t.Fatalf("expected %d bytes, got %d", network.CPacePointSize+network.X25519PubSize, len(blob))
	}

	gotCPace, gotX25519, err := network.ParseSenderHandshakeBlob(blob)
	if err != nil {
		t.Fatalf("ParseSenderHandshakeBlob: %v", err)
	}
	if string(gotCPace) != string(cpacePub) {
		t.Fatal("CPace pub mismatch")
	}
	if string(gotX25519) != string(x25519Pub) {
		t.Fatal("X25519 pub mismatch")
	}
}

func TestSenderHandshakeBlob_TooShort(t *testing.T) {
	_, _, err := network.ParseSenderHandshakeBlob([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

func TestReceiverHandshakeBlob_RoundTrip(t *testing.T) {
	cpacePub := make([]byte, network.CPacePointSize)
	x25519Pub := make([]byte, network.X25519PubSize)
	mlkemEk := make([]byte, network.MLKEMEncapKeySize)
	for i := range cpacePub {
		cpacePub[i] = byte(i)
	}
	for i := range x25519Pub {
		x25519Pub[i] = byte(i + 200)
	}
	for i := range mlkemEk {
		mlkemEk[i] = byte(i + 50)
	}

	blob := network.ReceiverHandshakeBlob(cpacePub, x25519Pub, mlkemEk)
	expectedLen := network.CPacePointSize + network.X25519PubSize + network.MLKEMEncapKeySize
	if len(blob) != expectedLen {
		t.Fatalf("expected %d bytes, got %d", expectedLen, len(blob))
	}

	gotCPace, gotX25519, gotMlkem, err := network.ParseReceiverHandshakeBlob(blob)
	if err != nil {
		t.Fatalf("ParseReceiverHandshakeBlob: %v", err)
	}
	if string(gotCPace) != string(cpacePub) {
		t.Fatal("CPace pub mismatch")
	}
	if string(gotX25519) != string(x25519Pub) {
		t.Fatal("X25519 pub mismatch")
	}
	if string(gotMlkem) != string(mlkemEk) {
		t.Fatal("MLKEM enc key mismatch")
	}
}

func TestReceiverHandshakeBlob_TooShort(t *testing.T) {
	_, _, _, err := network.ParseReceiverHandshakeBlob([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

func TestSenderBundleBlob_RoundTrip(t *testing.T) {
	kemCt := make([]byte, network.MLKEMCiphertextSize)
	encBundle := []byte("encrypted-endpoint-bundle-data")
	for i := range kemCt {
		kemCt[i] = byte(i)
	}

	blob := network.SenderBundleBlob(kemCt, encBundle)
	if len(blob) != network.MLKEMCiphertextSize+len(encBundle) {
		t.Fatalf("expected %d bytes, got %d", network.MLKEMCiphertextSize+len(encBundle), len(blob))
	}

	gotKemCt, gotEncBundle, err := network.ParseSenderBundleBlob(blob)
	if err != nil {
		t.Fatalf("ParseSenderBundleBlob: %v", err)
	}
	if string(gotKemCt) != string(kemCt) {
		t.Fatal("KEM ct mismatch")
	}
	if string(gotEncBundle) != string(encBundle) {
		t.Fatal("encrypted bundle mismatch")
	}
}

func TestSenderBundleBlob_TooShort(t *testing.T) {
	_, _, err := network.ParseSenderBundleBlob([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

// Ensure json round-trip of message type constants.
func TestMessageTypeSerialization(t *testing.T) {
	type msgTest struct {
		Type string `json:"type"`
	}
	data, err := json.Marshal(msgTest{Type: "allocate"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded msgTest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != "allocate" {
		t.Fatal("type mismatch")
	}
}
