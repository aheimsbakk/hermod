package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// startInternalTestServer creates a signaling server with a self-signed TLS
// certificate and returns the address and a cancel function. Callers must
// cancel to shut down the server.
func startInternalTestServer(t *testing.T) (string, *Server, func()) {
	t.Helper()

	// Generate a self-signed TLS certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	store := NewMemoryStore(0)
	rl := NewRateLimiter(100, 1000)
	logger := slog.Default()
	srv := NewServer(store, rl, rl, rl, 60*time.Second,
		DefaultMaxBlobsPerChannel, DefaultMaxCPaceFailures, certDER, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Serve(ctx, ln, tlsCfg)
	}()

	// Wait for the server to start listening.
	dialer := &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
		if err == nil {
			conn.Close()
			break
		}
	}

	return addr, srv, cancel
}

// TestStaleWaiterCleanupNoPanic verifies that handleAllocate does not panic
// when two or more stale waiter entries exist for a channel (M-01 regression
// test). The old code mutated the slice in place while iterating with range,
// causing an index-out-of-range panic on the second removal.
func TestStaleWaiterCleanupNoPanic(t *testing.T) {
	addr, srv, cancel := startInternalTestServer(t)
	defer cancel()

	dialer := &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	// Open a connection that will send MsgAllocate.
	newSender, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial newSender: %v", err)
	}
	defer newSender.Close()

	// Open two additional connections to use as stale waiter entries.
	staleConn1, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial stale1: %v", err)
	}
	defer staleConn1.Close()

	staleConn2, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial stale2: %v", err)
	}
	defer staleConn2.Close()

	// Inject two stale waiter entries directly into s.waiters[42].
	// These simulate waiter entries left behind after a relay goroutine
	// panicked before reaching its cleanup defer.
	srv.mu.Lock()
	srv.waiters[42] = []*wsConn{
		{conn: staleConn1, sender: false},
		{conn: staleConn2, sender: false},
	}
	srv.mu.Unlock()

	// Send MsgAllocate. The old code would panic here when iterating over
	// the two stale entries and removing them via swap-with-last. The fix
	// uses a survivor slice and handles any number of stale entries.
	if err := newSender.WriteJSON(Message{Type: MsgAllocate, ChannelID: 42}); err != nil {
		t.Fatalf("write allocate: %v", err)
	}

	// Read the response — must be MsgOK (not a panic/crash).
	newSender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp Message
	if err := newSender.ReadJSON(&resp); err != nil {
		t.Fatalf("read allocate response: %v", err)
	}
	if resp.Type != MsgOK {
		t.Fatalf("expected MsgOK, got %s (error: %s)", resp.Type, resp.Error)
	}

	// Verify the stale entries were removed and only the new sender remains.
	srv.mu.Lock()
	waiters := srv.waiters[42]
	srv.mu.Unlock()

	if len(waiters) != 1 {
		t.Fatalf("expected 1 waiter after stale cleanup, got %d", len(waiters))
	}
	if !waiters[0].sender {
		t.Fatal("expected remaining waiter to be a sender")
	}

	// Verify the server mutex was released after the stale cleanup by
	// allocating a second channel on a new connection. The original
	// sender's connection is now inside the relay loop, so using it for
	// a second allocate would be consumed by the relay as an unexpected
	// message type.
	secondSender, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial secondSender: %v", err)
	}
	defer secondSender.Close()

	if err := secondSender.WriteJSON(Message{Type: MsgAllocate, ChannelID: 43}); err != nil {
		t.Fatalf("write second allocate: %v", err)
	}
	secondSender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp2 Message
	if err := secondSender.ReadJSON(&resp2); err != nil {
		t.Fatalf("read second allocate response: %v", err)
	}
	if resp2.Type != MsgOK {
		t.Fatalf("expected MsgOK for second allocate, got %s (error: %s)", resp2.Type, resp2.Error)
	}
}

// TestStaleWaiterCleanupNoStaleEntries verifies that handleAllocate works
// correctly when there are no stale waiters (the common case).
func TestStaleWaiterCleanupNoStaleEntries(t *testing.T) {
	addr, srv, cancel := startInternalTestServer(t)
	defer cancel()

	dialer := &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	sender, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial sender: %v", err)
	}
	defer sender.Close()

	// Allocate channel 42 — no stale entries.
	if err := sender.WriteJSON(Message{Type: MsgAllocate, ChannelID: 42}); err != nil {
		t.Fatalf("write allocate: %v", err)
	}
	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp Message
	if err := sender.ReadJSON(&resp); err != nil {
		t.Fatalf("read allocate: %v", err)
	}
	if resp.Type != MsgOK {
		t.Fatalf("expected MsgOK, got %s (error: %s)", resp.Type, resp.Error)
	}

	// Verify waiter was added.
	srv.mu.Lock()
	waiters := srv.waiters[42]
	srv.mu.Unlock()

	if len(waiters) != 1 {
		t.Fatalf("expected exactly one waiter, got %d", len(waiters))
	}
}

// TestStaleWaiterCleanupThreeStale verifies the survivor-slice approach
// correctly handles three stale entries (more than the minimum two that
// triggered the M-01 panic).
func TestStaleWaiterCleanupThreeStale(t *testing.T) {
	addr, srv, cancel := startInternalTestServer(t)
	defer cancel()

	dialer := &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	newSender, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial newSender: %v", err)
	}
	defer newSender.Close()

	staleConns := make([]*websocket.Conn, 3)
	for i := range staleConns {
		c, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
		if err != nil {
			t.Fatalf("dial stale[%d]: %v", i, err)
		}
		defer c.Close()
		staleConns[i] = c
	}

	srv.mu.Lock()
	srv.waiters[42] = []*wsConn{
		{conn: staleConns[0], sender: false},
		{conn: staleConns[1], sender: false},
		{conn: staleConns[2], sender: false},
	}
	srv.mu.Unlock()

	if err := newSender.WriteJSON(Message{Type: MsgAllocate, ChannelID: 42}); err != nil {
		t.Fatalf("write allocate: %v", err)
	}
	newSender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp Message
	if err := newSender.ReadJSON(&resp); err != nil {
		t.Fatalf("read allocate response: %v", err)
	}
	if resp.Type != MsgOK {
		t.Fatalf("expected MsgOK, got %s (error: %s)", resp.Type, resp.Error)
	}

	srv.mu.Lock()
	waiters := srv.waiters[42]
	srv.mu.Unlock()

	if len(waiters) != 1 {
		t.Fatalf("expected 1 waiter after cleaning 3 stale entries, got %d", len(waiters))
	}
}

// TestDropChannelReleasesStoreEntry verifies that dropChannel deletes the
// channel from the store while holding s.mu, preventing a race where a new
// allocation with the same ID could be deleted by a deferred DeleteChannel
// (L-07 / SUM-09 regression test).
func TestDropChannelReleasesStoreEntry(t *testing.T) {
	_, srv, cancel := startInternalTestServer(t)
	defer cancel()

	// Allocate a channel through the store directly.
	if err := srv.store.AllocateChannel(99, 60*time.Second, ""); err != nil {
		t.Fatalf("allocate channel in store: %v", err)
	}

	// Verify the channel exists.
	if !srv.store.ChannelExists(99) {
		t.Fatal("expected channel 99 to exist before dropChannel")
	}

	// Call dropChannel — this must delete from both waiters and store.
	// No waiter connections to clean up; we just care about the store.
	srv.dropChannel(99)

	// Verify the channel is removed from the store.
	if srv.store.ChannelExists(99) {
		t.Fatal("expected channel 99 to be removed from store after dropChannel")
	}

	// Verify the channel can be re-allocated (no stale deletion race).
	if err := srv.store.AllocateChannel(99, 60*time.Second, ""); err != nil {
		t.Fatalf("re-allocate channel 99 after dropChannel: %v", err)
	}
}

// TestRelayErrorGenericMessage verifies that the relay loop sends the same
// generic error message regardless of whether the CPace failure limit has
// been reached. This prevents the server from leaking failure-counter state
// through error text (L-08 / SUM-05).
func TestRelayErrorGenericMessage(t *testing.T) {
	addr, _, cancel := startInternalTestServer(t)
	defer cancel()

	dialer := &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	// Open a sender connection and allocate a channel.
	sender, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("dial sender: %v", err)
	}
	defer sender.Close()

	if err := sender.WriteJSON(Message{Type: MsgAllocate, ChannelID: 44}); err != nil {
		t.Fatalf("write allocate: %v", err)
	}
	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp Message
	if err := sender.ReadJSON(&resp); err != nil {
		t.Fatalf("read allocate response: %v", err)
	}
	if resp.Type != MsgOK {
		t.Fatalf("expected MsgOK, got %s (error: %s)", resp.Type, resp.Error)
	}

	// Send an unexpected message type. The relay processes messages in a
	// goroutine started by handleAllocate. We send MsgJoin (invalid for
	// a sender) and expect a generic error.
	if err := sender.WriteJSON(Message{Type: MsgJoin, ChannelID: 44}); err != nil {
		t.Fatalf("write unexpected message: %v", err)
	}

	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var errResp Message
	if err := sender.ReadJSON(&errResp); err != nil {
		t.Fatalf("read error response: %v", err)
	}
	if errResp.Type != MsgError {
		t.Fatalf("expected MsgError, got %s", errResp.Type)
	}
	if errResp.Error == "" {
		t.Fatal("expected non-empty error message")
	}
	// The error must NOT contain "channel terminated" which would reveal
	// that the failure limit was reached.
	if strings.Contains(errResp.Error, "channel terminated") {
		t.Fatalf("error message must not leak failure state, got: %q", errResp.Error)
	}
}
