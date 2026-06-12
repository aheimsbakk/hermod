package server_test

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/server"
)

func startTestServer(t *testing.T) (string, func()) {
	return startTestServerWithLimits(t, server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures, nil)
}

// startTestServerWithLimits starts a test signaling server. certDER may be nil
// to disable the /cert endpoint, or the DER-encoded TLS certificate to enable it.
func startTestServerWithLimits(t *testing.T, maxBlobs, maxCPaceFailures int, certDER []byte) (string, func()) {
	rl := server.NewRateLimiter(100, 1000)
	return startTestServerWithRL(t, rl, rl, rl, maxBlobs, maxCPaceFailures, certDER)
}

// startTestServerWithRL starts a test signaling server with separate rate limiters.
func startTestServerWithRL(t *testing.T, certRL, wsRL, joinRL *server.RateLimiter, maxBlobs, maxCPaceFailures int, certDER []byte) (string, func()) {
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

	store := server.NewMemoryStore(0)
	logger := slog.Default()
	if certDER == nil {
		certDER = tlsCert.Certificate[0]
	}
	srv := server.NewServer(store, certRL, wsRL, joinRL, 60*time.Second, maxBlobs, maxCPaceFailures, certDER, logger)

	// Find a free port and keep the listener open to prevent port reuse.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find port: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		srv.Serve(ctx, ln, tlsCfg) //nolint:errcheck
	}()
	// Wait for the server to start listening
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
	}

	return addr, cancel
}

func dialTestWS(t *testing.T, addr string) *websocket.Conn {
	t.Helper()
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	conn, _, err := dialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	return conn
}

// TestServerConcurrentJoinRejectsDuplicateReceiver verifies the C-01 fix:
// two concurrent Join requests for the same channel cannot both succeed.
// Receivers stay connected after joining to prevent the relay cleanup from
// removing them from the waiters list before the second joiner checks.
func TestServerConcurrentJoinRejectsDuplicateReceiver(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	// Sender: allocate channel
	sender := dialTestWS(t, addr)
	defer sender.Close()
	sender.WriteJSON(server.Message{Type: server.MsgAllocate, ChannelID: 42})
	var allocResp server.Message
	if err := sender.ReadJSON(&allocResp); err != nil {
		t.Fatalf("allocate read: %v", err)
	}
	if allocResp.Type != server.MsgOK {
		t.Fatalf("expected MsgOK, got %s (error: %s)", allocResp.Type, allocResp.Error)
	}

	// Launch two concurrent joiners. Each stays connected (blocking on ReadJSON)
	// until the test ends, so the relay cleanup does not race against the check.
	type joinResult struct {
		msgType server.MsgType
		errMsg  string
	}
	results := make(chan joinResult, 2)
	done := make(chan struct{})

	for i := 0; i < 2; i++ {
		go func() {
			r := dialTestWS(t, addr)
			r.WriteJSON(server.Message{Type: server.MsgJoin, ChannelID: 42})
			r.SetReadDeadline(time.Now().Add(3 * time.Second))
			var resp server.Message
			if err := r.ReadJSON(&resp); err != nil {
				results <- joinResult{msgType: server.MsgType("error"), errMsg: err.Error()}
				<-done
				return
			}
			results <- joinResult{msgType: resp.Type, errMsg: resp.Error}
			// Stay connected so relay cleanup does not run until after check.
			<-done
		}()
	}

	okCount := 0
	errCount := 0
	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.msgType == server.MsgOK {
				okCount++
			} else {
				errCount++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for join results")
		}
	}
	close(done)

	if okCount != 1 {
		t.Fatalf("expected exactly 1 successful join, got %d", okCount)
	}
	if errCount != 1 {
		t.Fatalf("expected exactly 1 rejected join, got %d", errCount)
	}
}

func TestServerAllocateAndJoin(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	// Sender: allocate channel
	sender := dialTestWS(t, addr)
	defer sender.Close()

	sender.WriteJSON(server.Message{Type: server.MsgAllocate, ChannelID: 1234})
	var resp server.Message
	if err := sender.ReadJSON(&resp); err != nil {
		t.Fatalf("allocate read: %v", err)
	}
	if resp.Type != server.MsgOK {
		t.Fatalf("expected MsgOK, got %s (error: %s)", resp.Type, resp.Error)
	}

	// Receiver: join channel (async, since sender is waiting for MsgReady)
	done := make(chan struct{})
	go func() {
		defer close(done)
		receiver := dialTestWS(t, addr)
		defer receiver.Close()
		receiver.WriteJSON(server.Message{Type: server.MsgJoin, ChannelID: 1234})
		var joinResp server.Message
		if err := receiver.ReadJSON(&joinResp); err != nil {
			return
		}
	}()

	// Sender should receive MsgReady
	var readyMsg server.Message
	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := sender.ReadJSON(&readyMsg); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	if readyMsg.Type != server.MsgReady {
		t.Fatalf("expected MsgReady, got %s", readyMsg.Type)
	}
	<-done
}

func TestServerBlobRelay(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	sender := dialTestWS(t, addr)
	defer sender.Close()
	sender.WriteJSON(server.Message{Type: server.MsgAllocate, ChannelID: 5678})
	var allocResp server.Message
	sender.ReadJSON(&allocResp)

	receivedBlob := make(chan []byte, 1)
	go func() {
		receiver := dialTestWS(t, addr)
		defer receiver.Close()
		receiver.WriteJSON(server.Message{Type: server.MsgJoin, ChannelID: 5678})
		var joinResp server.Message
		receiver.ReadJSON(&joinResp)

		// Send a blob from receiver
		receiver.WriteJSON(server.Message{Type: server.MsgBlob, ChannelID: 5678, Payload: []byte("hello-from-receiver")})

		// Read the blob sender sends back
		var blobMsg server.Message
		receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
		receiver.ReadJSON(&blobMsg)
		if blobMsg.Type == server.MsgBlob {
			receivedBlob <- blobMsg.Payload
		} else {
			receivedBlob <- nil
		}
	}()

	// Wait for ready
	var readyMsg server.Message
	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	sender.ReadJSON(&readyMsg)

	// Read blob from receiver
	var senderBlobMsg server.Message
	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := sender.ReadJSON(&senderBlobMsg); err != nil {
		t.Fatalf("read blob at sender: %v", err)
	}
	if senderBlobMsg.Type != server.MsgBlob {
		t.Fatalf("expected MsgBlob at sender, got %s", senderBlobMsg.Type)
	}

	// Send blob from sender to receiver
	sender.WriteJSON(server.Message{Type: server.MsgBlob, ChannelID: 5678, Payload: []byte("hello-from-sender")})

	select {
	case rb := <-receivedBlob:
		if rb == nil {
			t.Fatal("receiver got nil blob")
		}
		if string(rb) != "hello-from-sender" {
			t.Fatalf("blob mismatch: %q", rb)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for relayed blob")
	}
}

func TestRunGC(t *testing.T) {
	store := server.NewMemoryStore(0)
	store.AllocateChannel(99, -time.Second, "")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	server.RunGC(ctx, store, 100*time.Millisecond)
	<-ctx.Done()

	// Channel 99 must have been purged by GC — the TTL was -1 second, and
	// RunGC ran with a 100ms interval for up to 300ms, giving it at least 2
	// opportunities to sweep.
	if err := store.StoreBlob(99, true, []byte("x")); err == nil {
		t.Error("channel 99 was not purged by GC — expired channel still accepts blobs")
	}
}

// TestServerBlobLimitEnforced verifies that the server rejects a MsgBlob once
// the per-channel hard cap is reached.
func TestServerBlobLimitEnforced(t *testing.T) {
	const limit = 2
	addr, cancel := startTestServerWithLimits(t, limit, server.DefaultMaxCPaceFailures, nil)
	defer cancel()

	sender := dialTestWS(t, addr)
	defer sender.Close()
	sender.WriteJSON(server.Message{Type: server.MsgAllocate, ChannelID: 7001})
	var allocResp server.Message
	if err := sender.ReadJSON(&allocResp); err != nil {
		t.Fatalf("read allocate resp: %v", err)
	}
	if allocResp.Type != server.MsgOK {
		t.Fatalf("expected MsgOK, got %s (error: %s)", allocResp.Type, allocResp.Error)
	}

	// Receiver joins so the relay loop on the sender side is active.
	go func() {
		r := dialTestWS(t, addr)
		defer r.Close()
		r.WriteJSON(server.Message{Type: server.MsgJoin, ChannelID: 7001})
		var j server.Message
		r.ReadJSON(&j)
		// Drain any forwarded blobs so the receiver goroutine does not block.
		r.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			var m server.Message
			if err := r.ReadJSON(&m); err != nil {
				return
			}
		}
	}()

	// Wait for MsgReady.
	var readyMsg server.Message
	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := sender.ReadJSON(&readyMsg); err != nil {
		t.Fatalf("read ready: %v", err)
	}

	// Send exactly `limit` blobs — all must succeed.
	for i := 0; i < limit; i++ {
		sender.WriteJSON(server.Message{
			Type:      server.MsgBlob,
			ChannelID: 7001,
			Payload:   []byte("data"),
		})
	}

	// The (limit+1)-th blob must trigger a MsgError response.
	sender.WriteJSON(server.Message{
		Type:      server.MsgBlob,
		ChannelID: 7001,
		Payload:   []byte("over-limit"),
	})

	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var errMsg server.Message
	if err := sender.ReadJSON(&errMsg); err != nil {
		t.Fatalf("expected MsgError for over-limit blob, got read error: %v", err)
	}
	if errMsg.Type != server.MsgError {
		t.Fatalf("expected MsgError, got %s", errMsg.Type)
	}
}

// TestServerCPaceFailureLimitEnforced verifies that the server drops all
// connections and invalidates a channel after maxCPaceFailures protocol
// violations.
func TestServerCPaceFailureLimitEnforced(t *testing.T) {
	// maxCPaceFailures=1 so a single bad message terminates the channel.
	addr, cancel := startTestServerWithLimits(t, server.DefaultMaxBlobsPerChannel, 1, nil)
	defer cancel()

	sender := dialTestWS(t, addr)
	defer sender.Close()
	sender.WriteJSON(server.Message{Type: server.MsgAllocate, ChannelID: 7002})
	var allocResp server.Message
	if err := sender.ReadJSON(&allocResp); err != nil {
		t.Fatalf("read allocate resp: %v", err)
	}
	if allocResp.Type != server.MsgOK {
		t.Fatalf("expected MsgOK, got %s", allocResp.Type)
	}

	// Receiver joins; keep a handle to verify it gets closed.
	receiverClosed := make(chan struct{})
	go func() {
		defer close(receiverClosed)
		r := dialTestWS(t, addr)
		defer r.Close()
		r.WriteJSON(server.Message{Type: server.MsgJoin, ChannelID: 7002})
		var j server.Message
		r.ReadJSON(&j)
		// Block until the connection is closed by the server.
		r.SetReadDeadline(time.Now().Add(5 * time.Second))
		var m server.Message
		r.ReadJSON(&m) // will return error when server closes the conn
	}()

	// Wait for MsgReady on the sender side.
	var readyMsg server.Message
	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := sender.ReadJSON(&readyMsg); err != nil {
		t.Fatalf("read ready: %v", err)
	}

	// Send an unexpected message type — triggers the failure counter.
	sender.WriteJSON(server.Message{Type: server.MsgType("bad"), ChannelID: 7002})

	// Sender must receive a MsgError.
	sender.SetReadDeadline(time.Now().Add(3 * time.Second))
	var errMsg server.Message
	if err := sender.ReadJSON(&errMsg); err != nil {
		t.Fatalf("expected MsgError after protocol violation, got read error: %v", err)
	}
	if errMsg.Type != server.MsgError {
		t.Fatalf("expected MsgError, got %s", errMsg.Type)
	}

	// Receiver must also have been disconnected by dropChannel.
	select {
	case <-receiverClosed:
		// expected
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: receiver connection was not closed after channel drop")
	}
}

// TestServerCertEndpoint verifies the /cert endpoint returns the DER-encoded
// TLS certificate.
func TestServerCertEndpoint(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get("https://" + addr + "/cert")
	if err != nil {
		t.Fatalf("GET /cert: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("expected Content-Type application/x-pem-file, got %q", resp.Header.Get("Content-Type"))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty certificate body")
	}
	// Verify it's valid PEM
	if string(body[:27]) != "-----BEGIN CERTIFICATE-----" {
		t.Fatal("expected PEM certificate format")
	}
}

// TestServerCertRateLimitIsolation verifies that exhausting the /cert rate
// limiter does not affect WebSocket connections (fix #6).
func TestServerCertRateLimitIsolation(t *testing.T) {
	// certRL: burst=1 (tight), rate near-zero so tokens don't refill during test.
	certRL := server.NewRateLimiter(0.001, 1)
	wsRL := server.NewRateLimiter(100, 1000)
	joinRL := server.NewRateLimiter(100, 1000)
	addr, cancel := startTestServerWithRL(t, certRL, wsRL, joinRL,
		server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures, nil)
	defer cancel()

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   5 * time.Second,
	}

	// First /cert request — should succeed (burst=1).
	resp, err := client.Get("https://" + addr + "/cert")
	if err != nil {
		t.Fatalf("first GET /cert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first /cert: expected 200, got %d", resp.StatusCode)
	}

	// Second /cert request — rate-limited (burst exhausted).
	resp, err = client.Get("https://" + addr + "/cert")
	if err != nil {
		t.Fatalf("second GET /cert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second /cert: expected 429, got %d", resp.StatusCode)
	}

	// WebSocket should still connect — its rate limiter is independent.
	wsDialer := &websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	conn, _, err := wsDialer.Dial("wss://"+addr+"/ws", nil)
	if err != nil {
		t.Fatalf("WS dial after cert rate-limit exhausted: %v", err)
	}
	conn.Close()
}

// TestServerJoinRateLimitBlocksEnumeration verifies that exhausting the join
// rate limiter prevents further join attempts (fix #4 channel enumeration).
func TestServerJoinRateLimitBlocksEnumeration(t *testing.T) {
	// joinRL: burst=1, rate near-zero so tokens don't refill during test.
	certRL := server.NewRateLimiter(100, 1000)
	wsRL := server.NewRateLimiter(100, 1000)
	joinRL := server.NewRateLimiter(0.001, 1)
	addr, cancel := startTestServerWithRL(t, certRL, wsRL, joinRL,
		server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures, nil)
	defer cancel()

	// Allocate a channel so we can attempt joins.
	sender := dialTestWS(t, addr)
	defer sender.Close()
	sender.WriteJSON(server.Message{Type: server.MsgAllocate, ChannelID: 9001})
	var allocResp server.Message
	if err := sender.ReadJSON(&allocResp); err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if allocResp.Type != server.MsgOK {
		t.Fatalf("allocate expected MsgOK, got %s", allocResp.Type)
	}

	// First join to a valid channel — allowed (burst=1).
	receiver1 := dialTestWS(t, addr)
	receiver1.WriteJSON(server.Message{Type: server.MsgJoin, ChannelID: 9001})
	var joinResp1 server.Message
	receiver1.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := receiver1.ReadJSON(&joinResp1); err != nil {
		t.Fatalf("first join read: %v", err)
	}
	if joinResp1.Type != server.MsgOK {
		t.Fatalf("first join expected MsgOK, got %s (error: %s)", joinResp1.Type, joinResp1.Error)
	}
	receiver1.Close()

	// Second join from the same IP — rate-limited (burst exhausted).
	receiver2 := dialTestWS(t, addr)
	receiver2.WriteJSON(server.Message{Type: server.MsgJoin, ChannelID: 9001})
	var joinResp2 server.Message
	receiver2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := receiver2.ReadJSON(&joinResp2); err != nil {
		t.Fatalf("second join read: %v", err)
	}
	if joinResp2.Type != server.MsgError {
		t.Fatalf("second join expected MsgError (rate-limited), got %s", joinResp2.Type)
	}
	if joinResp2.Error != "operation failed" {
		t.Fatalf("second join expected 'operation failed', got %q", joinResp2.Error)
	}
	receiver2.Close()
}

// TestServerJoinNonExistentChannelGenericError verifies that joining a
// non-existent channel returns "operation failed" instead of "channel not
// found", preventing channel enumeration (fix #4).
func TestServerJoinNonExistentChannelGenericError(t *testing.T) {
	addr, cancel := startTestServer(t)
	defer cancel()

	conn := dialTestWS(t, addr)
	defer conn.Close()

	conn.WriteJSON(server.Message{Type: server.MsgJoin, ChannelID: 9999})
	var resp server.Message
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("join read: %v", err)
	}
	if resp.Type != server.MsgError {
		t.Fatalf("expected MsgError, got %s", resp.Type)
	}
	if resp.Error != "operation failed" {
		t.Fatalf("expected 'operation failed', got %q", resp.Error)
	}
}
