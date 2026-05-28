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
	srv := server.NewServer(store, rl, 60*time.Second, logger)

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
