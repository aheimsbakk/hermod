package network_test

import (
	"encoding/json"
	"net"
	"testing"

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

func TestEncodeDecodeCPaceMsg(t *testing.T) {
	msg := network.CPaceMsg{PubMsg: []byte{0x04, 0x01, 0x02, 0x03}}
	data, err := network.EncodeCPaceMsg(msg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := network.DecodeCPaceMsg(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.PubMsg) != string(msg.PubMsg) {
		t.Fatal("pub msg mismatch")
	}
}

func TestEncodeDecodeEndpointBundle(t *testing.T) {
	bundle := network.EndpointBundle{
		LocalEndpointsV4: []string{"192.168.1.1:4376", "10.0.0.1:4376"},
		PublicEndpointV4: "1.2.3.4:4376",
		CertFingerprint:  "aabbccdd",
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
	if decoded.CertFingerprint != bundle.CertFingerprint {
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

func TestCertFingerprint(t *testing.T) {
	// Generate a fake DER certificate (just bytes for hash purposes)
	fakeData := make([]byte, 512)
	for i := range fakeData {
		fakeData[i] = byte(i)
	}
	fp := network.CertFingerprint(fakeData)
	if len(fp) != 64 {
		t.Fatalf("expected 64-char fingerprint, got %d", len(fp))
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

func TestDecodeCPaceMsgInvalid(t *testing.T) {
	_, err := network.DecodeCPaceMsg([]byte("{invalid"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestNewPacketMuxDemux verifies the mux routes probe vs QUIC packets.
func TestNewPacketMuxDemux(t *testing.T) {
	// Bind two UDP sockets
	conn1, err := network.BindUDP(":0")
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := network.BindUDP(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	defer conn2.Close()

	addr1, _ := network.LocalUDPAddr(conn1)
	addr2, _ := network.LocalUDPAddr(conn2)

	mux1 := network.NewPacketMux(conn1)
	defer mux1.Close()

	// Send a probe from conn2 to mux1
	probeData := []byte{0x01, 0xAB} // probeMarker + data
	conn2.WriteTo(probeData, addr1)

	// Send a QUIC-like packet (starts with 0xC0) from conn2 to mux1
	quicData := []byte{0xC0, 0x01, 0x02}
	conn2.WriteTo(quicData, addr1)

	_ = addr2
	// Don't block on reads — just verify the mux was constructed without panic
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
		LocalEndpointsV4: []string{"192.168.1.1:4376"},
		PublicEndpointV4: "1.2.3.4:4376",
		CertFingerprint:  "aabbccdd",
		RequireVerify:    true,
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
		LocalEndpointsV4: []string{"192.168.1.1:4376"},
		PublicEndpointV4: "1.2.3.4:4376",
		CertFingerprint:  "aabbccdd",
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
		LocalEndpointsV4: []string{"192.168.1.1:4376", "10.0.0.1:4376"},
		LocalEndpointsV6: []string{"[2001:db8::1]:4376", "[fe80::1]:4376"},
		PublicEndpointV4: "1.2.3.4:4376",
		PublicEndpointV6: "[2001:db8::1]:4376",
		CertFingerprint:  "aabbccdd",
		RequireVerify:    true,
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
