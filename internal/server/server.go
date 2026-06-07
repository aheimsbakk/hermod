// Package server: WebSocket signaling relay.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxMessageSize = 65536 // 64 KiB per signaling message

	// DefaultMaxBlobsPerChannel is the default hard cap on relayed blobs per channel.
	DefaultMaxBlobsPerChannel = 10
	// DefaultMaxCPaceFailures is the default limit on CPace handshake failures per channel.
	DefaultMaxCPaceFailures = 3
)

// MsgType identifies signaling message types.
type MsgType string

const (
	MsgAllocate  MsgType = "allocate"
	MsgJoin      MsgType = "join"
	MsgHandshake MsgType = "handshake"
	MsgBlob      MsgType = "blob"
	MsgError     MsgType = "error"
	MsgOK        MsgType = "ok"
	MsgReady     MsgType = "ready"
)

// Message is the signaling wire format.
type Message struct {
	Type      MsgType `json:"type"`
	ChannelID uint16  `json:"channel_id,omitempty"`
	Payload   []byte  `json:"payload,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Server is the hermod signaling server.
type Server struct {
	store              SignalingStore
	rl                 *RateLimiter
	ttl                time.Duration
	maxBlobsPerChannel int
	maxCPaceFailures   int
	certDER            []byte // DER-encoded server certificate for the /cert endpoint
	upgrader           websocket.Upgrader
	httpServer         *http.Server
	logger             *slog.Logger

	mu      sync.Mutex
	waiters map[uint16][]*wsConn // pending peer connections
}

type wsConn struct {
	conn   *websocket.Conn
	sender bool
}

// NewServer constructs a new signaling Server.
// certDER is the DER-encoded server TLS certificate served via the /cert endpoint;
// pass nil to disable the /cert endpoint.
// maxBlobsPerChannel caps the number of relayed blobs per channel; use
// DefaultMaxBlobsPerChannel for the spec default.
// maxCPaceFailures caps CPace protocol violations before the channel is
// invalidated; use DefaultMaxCPaceFailures for the spec default.
func NewServer(store SignalingStore, rl *RateLimiter, ttl time.Duration, maxBlobsPerChannel, maxCPaceFailures int, certDER []byte, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:              store,
		rl:                 rl,
		ttl:                ttl,
		maxBlobsPerChannel: maxBlobsPerChannel,
		maxCPaceFailures:   maxCPaceFailures,
		certDER:            certDER,
		logger:             logger,
		waiters:            make(map[uint16][]*wsConn),
		upgrader: websocket.Upgrader{
			// Reject browser-sourced cross-origin WebSocket connections (L-06).
			// Non-browser clients (CLI) do not set an Origin header, so this
			// allows all legitimate hermod peers while blocking CSRF-style attacks.
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == ""
			},
		},
	}
}

// ListenAndServe starts the HTTPS/WebSocket server on addr using the given TLS config.
func (s *Server) ListenAndServe(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/cert", s.handleCert)

	s.httpServer = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	s.logger.Info("Signaling server ready", "addr", addr)

	// Start background goroutine to evict stale rate-limit buckets.
	// Buckets inactive for more than 30 minutes are removed. Without this,
	// the bucket map grows unboundedly for every distinct source IP (M-03).
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	defer cleanupCancel()
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-ticker.C:
				s.rl.Cleanup(30 * time.Minute)
				s.logger.Debug("Rate limiter bucket cleanup ran")
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.Serve(tlsLn)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("Shutdown signal received — stopping server")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := s.httpServer.Shutdown(shutCtx)
		if err != nil {
			s.logger.Error("Server shutdown returned an error", "err", err)
		} else {
			s.logger.Info("Server shutdown complete")
		}
		return err
	case err := <-errCh:
		if err != nil {
			s.logger.Error("Server exited with an error", "err", err)
		}
		return err
	}
}

// Addr returns the listening address. Must be called after the server is started.
func (s *Server) Addr() string {
	if s.httpServer != nil {
		return s.httpServer.Addr
	}
	return ""
}

// handleCert serves the server's TLS certificate as PEM for client pinning.
// Clients can hash the DER bytes inside the PEM block with SHA-256 to obtain
// the fingerprint they should store via `hermod trust`.
// Rate limiting is applied to prevent abuse (M-05).
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if !s.rl.Allow(r.RemoteAddr) {
		s.logger.Warn("cert endpoint rate-limited", "remote_addr", r.RemoteAddr)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	if len(s.certDER) == 0 {
		http.Error(w, "certificate not available", http.StatusNotFound)
		return
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.certDER})
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pemBlock)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pemBlock)
}

// handleWS handles WebSocket connections from clients.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	s.logger.Debug("WebSocket upgrade request received", "remote_addr", remoteAddr)

	if !s.rl.Allow(remoteAddr) {
		s.logger.Warn("Request rate-limited", "remote_addr", remoteAddr)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("WebSocket upgrade failed", "remote_addr", remoteAddr, "err", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(maxMessageSize)

	s.logger.Debug("WebSocket connection established", "remote_addr", remoteAddr)
	s.serveClient(conn, remoteAddr)
	s.logger.Debug("WebSocket connection closed", "remote_addr", remoteAddr)
}

func (s *Server) serveClient(conn *websocket.Conn, remoteAddr string) {
	// Read first message to determine role
	var initMsg Message
	if err := conn.ReadJSON(&initMsg); err != nil {
		s.logger.Debug("Failed to read first message from client", "remote_addr", remoteAddr, "err", err)
		return
	}
	s.logger.Debug("First message received from client", "remote_addr", remoteAddr, "type", initMsg.Type, "channel_id", initMsg.ChannelID)

	switch initMsg.Type {
	case MsgAllocate:
		s.handleAllocate(conn, remoteAddr, initMsg.ChannelID)
	case MsgJoin:
		s.handleJoin(conn, remoteAddr, initMsg.ChannelID, initMsg.Payload)
	default:
		s.logger.Warn("Unknown first message type from client", "remote_addr", remoteAddr, "type", initMsg.Type)
		writeError(conn, "unknown init message type")
	}
}

// handleAllocate processes a sender's channel allocation request.
func (s *Server) handleAllocate(conn *websocket.Conn, remoteAddr string, channelID uint16) {
	s.logger.Debug("Allocating channel", "channel_id", channelID, "remote_addr", remoteAddr)
	if err := s.store.AllocateChannel(channelID, s.ttl); err != nil {
		s.logger.Warn("Channel allocation failed", "channel_id", channelID, "remote_addr", remoteAddr, "err", err)
		writeError(conn, "channel allocation failed")
		return
	}
	// Reply with public IP (STUN-like)
	host, _, _ := net.SplitHostPort(remoteAddr)
	payload, _ := json.Marshal(map[string]string{"public_ip": host})
	conn.WriteJSON(Message{Type: MsgOK, ChannelID: channelID, Payload: payload})
	s.logger.Info("Channel allocated", "channel_id", channelID, "sender_ip", host, "ttl", s.ttl)

	wsc := &wsConn{conn: conn, sender: true}
	s.mu.Lock()
	s.waiters[channelID] = append(s.waiters[channelID], wsc)
	s.mu.Unlock()

	// Now relay blobs between peers
	s.relay(conn, channelID, true)
}

// handleJoin processes a receiver's join request.
func (s *Server) handleJoin(conn *websocket.Conn, remoteAddr string, channelID uint16, _ []byte) {
	s.logger.Debug("Receiver joining channel", "channel_id", channelID, "remote_addr", remoteAddr)

	// Reject join for channels that were never allocated (M-05).
	if !s.store.ChannelExists(channelID) {
		s.logger.Warn("Receiver attempted to join non-existent channel",
			"channel_id", channelID, "remote_addr", remoteAddr)
		writeError(conn, "channel not found")
		return
	}

	// Check for existing receiver AND add the new one under a single lock
	// to prevent a TOCTOU race (C-01). Two concurrent joins must not both
	// pass the check before either adds itself.
	s.mu.Lock()
	for _, w := range s.waiters[channelID] {
		if !w.sender {
			s.mu.Unlock()
			s.logger.Warn("Receiver already registered for channel — rejecting duplicate join",
				"channel_id", channelID, "remote_addr", remoteAddr)
			writeError(conn, "channel already has a receiver")
			return
		}
	}

	wsc := &wsConn{conn: conn, sender: false}
	s.waiters[channelID] = append(s.waiters[channelID], wsc)
	// Notify sender that receiver has joined
	for _, w := range s.waiters[channelID] {
		if w.sender {
			w.conn.WriteJSON(Message{Type: MsgReady, ChannelID: channelID})
			s.logger.Debug("Sent ready signal to sender", "channel_id", channelID)
			break
		}
	}
	s.mu.Unlock()

	host, _, _ := net.SplitHostPort(remoteAddr)
	payload, _ := json.Marshal(map[string]string{"public_ip": host})
	conn.WriteJSON(Message{Type: MsgOK, ChannelID: channelID, Payload: payload})
	s.logger.Info("Receiver joined channel", "channel_id", channelID, "receiver_ip", host)

	s.relay(conn, channelID, false)
}

// relay reads handshake blobs from one peer and forwards them to the other.
func (s *Server) relay(conn *websocket.Conn, channelID uint16, isSender bool) {
	role := "receiver"
	if isSender {
		role = "sender"
	}
	s.logger.Debug("Relay loop started", "channel_id", channelID, "role", role)
	defer func() {
		s.mu.Lock()
		conns := s.waiters[channelID]
		updated := conns[:0]
		for _, w := range conns {
			if w.conn != conn {
				updated = append(updated, w)
			}
		}
		if len(updated) == 0 {
			delete(s.waiters, channelID)
			s.logger.Debug("All peers disconnected — channel removed", "channel_id", channelID)
		} else {
			s.waiters[channelID] = updated
		}
		s.mu.Unlock()
		s.logger.Debug("Relay loop ended", "channel_id", channelID, "role", role)
	}()

	blobCount := 0
	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			s.logger.Debug("Peer disconnected from relay", "channel_id", channelID, "role", role, "err", err)
			return
		}

		switch msg.Type {
		case MsgBlob:
			blobCount++
			if blobCount > s.maxBlobsPerChannel {
				s.logger.Warn("Blob limit exceeded — closing connection",
					"channel_id", channelID, "role", role,
					"count", blobCount, "limit", s.maxBlobsPerChannel)
				writeError(conn, "blob limit exceeded")
				return
			}
			s.logger.Debug("Blob received from peer — forwarding", "channel_id", channelID, "role", role, "blob_num", blobCount, "size_bytes", len(msg.Payload))
			if err := s.store.StoreBlob(channelID, isSender, msg.Payload); err != nil {
				s.logger.Error("Failed to store blob", "channel_id", channelID, "role", role, "err", err)
				if s.recordFailureAndDrop(channelID) {
					writeError(conn, "store blob failed: channel terminated")
					return
				}
				writeError(conn, "store blob failed")
				return
			}
			// Forward blob to peer
			s.mu.Lock()
			forwarded := false
			for _, w := range s.waiters[channelID] {
				if w.sender != isSender {
					w.conn.WriteJSON(Message{
						Type:      MsgBlob,
						ChannelID: channelID,
						Payload:   msg.Payload,
					})
					forwarded = true
					break
				}
			}
			s.mu.Unlock()
			if !forwarded {
				s.logger.Warn("No peer available to receive blob", "channel_id", channelID, "role", role)
			} else {
				s.logger.Debug("Blob forwarded to peer", "channel_id", channelID, "blob_num", blobCount)
			}

		default:
			s.logger.Warn("Unexpected message type in relay", "channel_id", channelID, "role", role, "type", msg.Type)
			if s.recordFailureAndDrop(channelID) {
				writeError(conn, "unexpected message type: channel terminated")
				return
			}
			writeError(conn, "unexpected message type")
			return
		}
	}
}

// dropChannel closes all peer connections for channelID, sends them a final
// error, and purges the channel from the store. It is safe to call even if the
// channel has already been removed.
func (s *Server) dropChannel(channelID uint16) {
	s.mu.Lock()
	conns := s.waiters[channelID]
	delete(s.waiters, channelID)
	s.mu.Unlock()

	for _, w := range conns {
		_ = w.conn.WriteJSON(Message{Type: MsgError, Error: "channel terminated: limit exceeded"})
		w.conn.Close()
	}
	_ = s.store.DeleteChannel(channelID)
}

// recordFailureAndDrop records a protocol failure for the channel. If the
// failure count reaches s.maxCPaceFailures it drops the channel and returns
// true so the caller can exit the relay loop.
func (s *Server) recordFailureAndDrop(channelID uint16) bool {
	n, err := s.store.RecordFailure(channelID)
	if err != nil {
		// Channel may have already been deleted; treat as terminal.
		return true
	}
	if n >= s.maxCPaceFailures {
		s.logger.Warn("CPace failure limit reached — dropping channel",
			"channel_id", channelID, "failures", n, "limit", s.maxCPaceFailures)
		s.dropChannel(channelID)
		return true
	}
	return false
}

func writeError(conn *websocket.Conn, msg string) {
	conn.WriteJSON(Message{Type: MsgError, Error: msg})
}
