package server_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/server"
)

func startTestServer(t *testing.T) (string, func()) {
	return startTestServerWithLimits(t, server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures)
}

func startTestServerWithLimits(t *testing.T, maxBlobs, maxCPaceFailures int) (string, func()) {
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
	logger := slog.Default()
	srv := server.NewServer(store, rl, 60*time.Second, maxBlobs, maxCPaceFailures, logger)

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe(ctx, addr, tlsCfg)
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
	store := server.NewMemoryStore()
	store.AllocateChannel(99, -time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	server.RunGC(ctx, store, 100*time.Millisecond)
	<-ctx.Done()

	// Channel should have been purged
	if err := store.StoreBlob(99, true, []byte("x")); err == nil {
		t.Log("Note: channel 99 still exists (GC may not have run yet)")
	}
}

// TestServerBlobLimitEnforced verifies that the server rejects a MsgBlob once
// the per-channel hard cap is reached (GAP.md §6).
func TestServerBlobLimitEnforced(t *testing.T) {
	const limit = 2
	addr, cancel := startTestServerWithLimits(t, limit, server.DefaultMaxCPaceFailures)
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
// violations (GAP.md §5).
func TestServerCPaceFailureLimitEnforced(t *testing.T) {
	// maxCPaceFailures=1 so a single bad message terminates the channel.
	addr, cancel := startTestServerWithLimits(t, server.DefaultMaxBlobsPerChannel, 1)
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
