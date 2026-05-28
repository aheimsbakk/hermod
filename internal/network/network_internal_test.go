// Package network internal tests (white-box) for unexported types.
package network

import (
	"net"
	"testing"
	"time"
)

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
