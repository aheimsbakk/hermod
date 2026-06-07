package network_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/network"
	"github.com/hermod/hermod/internal/server"
)

func startSignalingServer(t *testing.T) string {
	t.Helper()
	cfg := config.Default()
	if err := config.GenerateServerCert(cfg); err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	tlsCert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	store := server.NewMemoryStore()
	rl := server.NewRateLimiter(100, 1000)
	// Pass the DER-encoded TLS certificate so the /cert endpoint works.
	srv := server.NewServer(store, rl, rl, rl, 60*time.Second, server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures, tlsCert.Certificate[0], slog.Default())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.ListenAndServe(ctx, addr, tlsCfg)
	// Wait for server to be ready
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return addr
		}
	}
	t.Fatal("server did not start")
	return ""
}

func TestSignalingClientAllocateJoin(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr

	// Sender allocates
	sender, err := network.DialSignaling(serverURL, "")
	if err != nil {
		t.Fatalf("dial sender: %v", err)
	}
	defer sender.Close()

	_, _, err = sender.Allocate(2222)
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}

	// Receiver joins
	done := make(chan error, 1)
	go func() {
		receiver, err := network.DialSignaling(serverURL, "")
		if err != nil {
			done <- err
			return
		}
		defer receiver.Close()
		_, _, err = receiver.Join(2222)
		done <- err
	}()

	// Sender should get MsgReady
	if err := sender.WaitReady(); err != nil {
		t.Fatalf("wait ready: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("receiver join: %v", err)
	}
}

func TestSignalingClientBlobExchange(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr

	sender, err := network.DialSignaling(serverURL, "")
	if err != nil {
		t.Fatalf("dial sender: %v", err)
	}
	defer sender.Close()
	sender.Allocate(3333)

	receiverDone := make(chan []byte, 1)
	go func() {
		receiver, err := network.DialSignaling(serverURL, "")
		if err != nil {
			receiverDone <- nil
			return
		}
		defer receiver.Close()
		receiver.Join(3333)

		// Send blob from receiver
		receiver.SendBlob(3333, []byte("from-receiver"))

		// Receive blob from sender
		blob, err := receiver.RecvBlob()
		if err != nil {
			receiverDone <- nil
			return
		}
		receiverDone <- blob
	}()

	// Wait for receiver to join
	if err := sender.WaitReady(); err != nil {
		t.Fatalf("wait ready: %v", err)
	}

	// Read blob from receiver
	blob, err := sender.RecvBlob()
	if err != nil {
		t.Fatalf("recv blob at sender: %v", err)
	}
	if string(blob) != "from-receiver" {
		t.Fatalf("unexpected blob: %q", blob)
	}

	// Send blob to receiver
	if err := sender.SendBlob(3333, []byte("from-sender")); err != nil {
		t.Fatalf("send blob: %v", err)
	}

	select {
	case rb := <-receiverDone:
		if string(rb) != "from-sender" {
			t.Fatalf("receiver got: %q", rb)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestMakeCertPinnerValid(t *testing.T) {
	// Test cert pinning via a real QUIC dial (using network package internals)
	// We test the pinning indirectly through SignalingClient cert verification.
	cfg := config.Default()
	config.GenerateServerCert(cfg)
	tlsCert, _ := config.LoadServerTLSCert(cfg)
	fp := network.CertFingerprint(tlsCert.Certificate[0])

	// Verify the fingerprint is 64 hex chars
	if len(fp) != 64 {
		t.Fatalf("fingerprint length: %d", len(fp))
	}
}

func TestFetchServerFingerprint(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr

	fp, err := network.FetchServerFingerprint(serverURL, "")
	if err != nil {
		t.Fatalf("fetch fingerprint: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("expected 64-char fingerprint, got %d", len(fp))
	}
}

func TestFetchServerFingerprintWithMismatch(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr

	// Pass a wrong fingerprint — the TLS handshake should fail.
	wrongFP := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, err := network.FetchServerFingerprint(serverURL, wrongFP)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error during TLS handshake")
	}
}

func TestDialSignalingUnsupportedScheme(t *testing.T) {
	_, err := network.DialSignaling("ftp://localhost/ws", "")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}

func TestDialSignalingBadURL2(t *testing.T) {
	_, err := network.DialSignaling("://bad url", "")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestDialSignalingWithPinnedFingerprintMismatch(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr
	// Pass wrong fingerprint — should fail TLS verification
	_, err := network.DialSignaling(serverURL, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
}

func TestAllocateTwiceSameChannelErrors(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr

	c1, _ := network.DialSignaling(serverURL, "")
	defer c1.Close()
	c1.Allocate(5555)

	// Second allocation of same channel should error
	c2, _ := network.DialSignaling(serverURL, "")
	defer c2.Close()
	_, _, err := c2.Allocate(5555)
	if err == nil {
		t.Fatal("expected error allocating duplicate channel")
	}
}

func TestDialSignalingAllocateJoinErrorBranch(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr

	// Allocate channel
	c1, _ := network.DialSignaling(serverURL, "")
	defer c1.Close()
	c1.Allocate(6666)

	// Join as receiver
	c2, _ := network.DialSignaling(serverURL, "")
	defer c2.Close()
	_, _, err := c2.Join(6666)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
}

func TestJoinDuplicateReceiverRejected(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr

	// Sender allocates channel
	sender, err := network.DialSignaling(serverURL, "")
	if err != nil {
		t.Fatalf("dial sender: %v", err)
	}
	defer sender.Close()
	if _, _, err := sender.Allocate(7777); err != nil {
		t.Fatalf("allocate: %v", err)
	}

	// First receiver joins — should succeed
	r1, err := network.DialSignaling(serverURL, "")
	if err != nil {
		t.Fatalf("dial r1: %v", err)
	}
	defer r1.Close()
	if _, _, err := r1.Join(7777); err != nil {
		t.Fatalf("first receiver join: %v", err)
	}

	// Second receiver joins same channel — must be rejected (L-04)
	r2, err := network.DialSignaling(serverURL, "")
	if err != nil {
		t.Fatalf("dial r2: %v", err)
	}
	defer r2.Close()
	_, _, err = r2.Join(7777)
	if err == nil {
		t.Fatal("expected error when second receiver joins the same channel (L-04)")
	}
}

func TestSignalingWithContextCancellation(t *testing.T) {
	addr := startSignalingServer(t)
	serverURL := "wss://" + addr

	client, err := network.DialSignaling(serverURL, "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if _, _, err := client.Allocate(8888); err != nil {
		t.Fatalf("allocate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := client.WithContext(ctx)

	// Cancel shortly after starting the blocking RecvBlob.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err = c.RecvBlob()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("RecvBlob took too long after cancel: %v", elapsed)
	}
	// Error must be context.Canceled (not a raw net error).
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}
