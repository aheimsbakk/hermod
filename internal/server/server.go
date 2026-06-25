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
	"strings"
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
	certRL             *RateLimiter // /cert HTTP endpoint
	wsRL               *RateLimiter // WebSocket upgrade
	joinRL             *RateLimiter // join attempts (per-IP, channel enumeration)
	ttl                time.Duration
	maxBlobsPerChannel int
	maxCPaceFailures   int
	certDER            []byte // DER-encoded server certificate for the /cert endpoint
	upgrader           websocket.Upgrader
	httpServer         *http.Server
	logger             *slog.Logger

	mu         sync.Mutex
	waiters    map[uint16][]*wsConn // pending peer connections
	udpReflect *udpReflector        // UDP reflection for CGNAT address discovery; nil if unavailable

	// wsIdleTimeout is the read deadline for idle WebSocket connections.
	// Set from the --ttl flag. If no data (including pong) is received within
	// this period the connection is closed, preventing stale waiters from
	// blocking channel reuse.
	wsIdleTimeout time.Duration
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
func NewServer(store SignalingStore, certRL, wsRL, joinRL *RateLimiter, ttl time.Duration, maxBlobsPerChannel, maxCPaceFailures int, certDER []byte, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:              store,
		certRL:             certRL,
		wsRL:               wsRL,
		joinRL:             joinRL,
		ttl:                ttl,
		wsIdleTimeout:      ttl,
		maxBlobsPerChannel: maxBlobsPerChannel,
		maxCPaceFailures:   maxCPaceFailures,
		certDER:            certDER,
		logger:             logger,
		waiters:            make(map[uint16][]*wsConn),
		upgrader: websocket.Upgrader{
			// Reject browser-sourced cross-origin WebSocket connections.
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
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.Serve(ctx, ln, tlsCfg)
}

// Serve starts the HTTPS/WebSocket server on the given listener using the TLS
// config.  The caller owns the listener; it is closed when the server shuts down.
func (s *Server) Serve(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/cert", s.handleCert)

	tlsLn := tls.NewListener(ln, tlsCfg)

	s.httpServer = &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start UDP reflection on the same port for CGNAT address discovery.
	// This allows peers behind CGNAT to learn their external UDP address
	// from the server. If the UDP bind fails (e.g. port unavailable), the
	// reflector is nil and clients will fall back to the current behaviour.
	s.udpReflect = startUDPReflector(ctx, ln.Addr().String())
	defer func() {
		if s.udpReflect != nil {
			s.udpReflect.Close()
		}
	}()

	if s.udpReflect != nil {
		s.logger.Info("UDP reflection enabled for CGNAT address discovery", "addr", ln.Addr().String())
	}

	s.logger.Info("Signaling server ready", "addr", ln.Addr().String())

	// Start background goroutine to evict stale rate-limit buckets.
	// Buckets inactive for more than 30 minutes are removed. Without this,
	// the bucket map grows unboundedly for every distinct source IP.
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
				s.certRL.Cleanup(30 * time.Minute)
				s.wsRL.Cleanup(30 * time.Minute)
				s.joinRL.Cleanup(30 * time.Minute)
				// Purge expired channel store entries and clean up any
				// stale waiters whose store entries have expired.
				expiredIDs, _ := s.store.PurgeExpired()
				if len(expiredIDs) > 0 {
					s.purgeExpiredWaiters(expiredIDs)
				}
				s.logger.Debug("Rate limiter bucket cleanup completed")
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

// handleCert serves the server's TLS certificate as PEM for client pinning.
// Clients can hash the DER bytes inside the PEM block with SHA-256 to obtain
// the fingerprint they should store via `hermod trust`.
// Rate limiting is applied to prevent abuse.
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if !s.certRL.Allow(r.RemoteAddr) {
		s.logger.Warn("cert endpoint rate-limited", "remote_addr", r.RemoteAddr)
		http.Error(w, "Too many requests. Try again later.", http.StatusTooManyRequests)
		return
	}
	if len(s.certDER) == 0 {
		http.Error(w, "Certificate not available", http.StatusNotFound)
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

	if !s.wsRL.Allow(remoteAddr) {
		s.logger.Warn("Request rate-limited", "remote_addr", remoteAddr)
		http.Error(w, "Too many requests. Try again later.", http.StatusTooManyRequests)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("WebSocket upgrade failed", "remote_addr", remoteAddr, "err", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(maxMessageSize)
	// Enforce an idle timeout so stale connections cannot block channel reuse.
	// The deadline is extended on every pong from the client.
	// The timeout is set from the --ttl flag (default 600s).
	conn.SetReadDeadline(time.Now().Add(s.wsIdleTimeout))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(s.wsIdleTimeout))
		return nil
	})

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
		writeError(conn, "first message must be 'allocate' or 'join'")
	}
}

// handleAllocate processes a sender's channel allocation request.
func (s *Server) handleAllocate(conn *websocket.Conn, remoteAddr string, channelID uint16) {
	s.logger.Debug("Allocating channel", "channel_id", channelID, "remote_addr", remoteAddr)
	if err := s.store.AllocateChannel(channelID, s.ttl, remoteAddr); err != nil {
		s.logger.Warn("Channel allocation failed", "channel_id", channelID, "remote_addr", remoteAddr, "err", err)
		writeError(conn, "could not allocate channel")
		return
	}
	// Remove any stale waiters that were left behind after the store entry
	// expired. This prevents a stale sender slot from being matched to a new
	// receiver. Build a survivor slice instead of mutating in place — the
	// old swap-with-last pattern panics when two or more entries are removed
	// because the range iterator advances past the shrinking slice (M-01).
	s.mu.Lock()
	survivors := make([]*wsConn, 0, len(s.waiters[channelID]))
	for _, w := range s.waiters[channelID] {
		if w.conn == conn {
			survivors = append(survivors, w)
			continue
		}
		s.logger.Warn("Removing stale waiter for channel", "channel_id", channelID, "sender", w.sender)
		w.conn.Close()
	}
	s.waiters[channelID] = survivors
	s.mu.Unlock()

	host, _, _ := net.SplitHostPort(remoteAddr)
	respMap := publicIPResponse(host)
	payload, _ := json.Marshal(respMap)

	wsc := &wsConn{conn: conn, sender: true}
	s.mu.Lock()
	s.waiters[channelID] = append(s.waiters[channelID], wsc)

	var receiverConn *websocket.Conn
	for _, w := range s.waiters[channelID] {
		if !w.sender {
			receiverConn = w.conn
			break
		}
	}

	// Send responses while holding the lock so handleJoin cannot
	// write to the same connection concurrently.
	conn.WriteJSON(Message{Type: MsgOK, ChannelID: channelID, Payload: payload})
	if receiverConn != nil {
		conn.WriteJSON(Message{Type: MsgReady, ChannelID: channelID})
	}
	s.mu.Unlock()

	s.logger.Info("Channel allocated",
		"channel_id", channelID,
		"public_ipv4", respMap["public_ipv4"],
		"public_ipv6", respMap["public_ipv6"],
		"ttl", s.ttl)

	if receiverConn != nil {
		s.logger.Debug("Sent ready signal to sender (receiver joined early)", "channel_id", channelID)
	}

	// Now relay blobs between peers
	s.relay(conn, channelID, true)
}

// handleJoin processes a receiver's join request.
func (s *Server) handleJoin(conn *websocket.Conn, remoteAddr string, channelID uint16, _ []byte) {
	s.logger.Debug("Receiver joining channel", "channel_id", channelID, "remote_addr", remoteAddr)

	// Rate-limit join attempts per-IP to slow channel enumeration (L-09).
	if !s.joinRL.Allow(remoteAddr) {
		s.logger.Warn("Join rate-limited", "channel_id", channelID, "remote_addr", remoteAddr)
		writeError(conn, "operation failed")
		return
	}

	// Reject join for channels that were never allocated.
	// Use a generic error message so clients cannot distinguish between
	// non-existent channels, duplicate receivers, and transient failures.
	if !s.store.ChannelExists(channelID) {
		s.logger.Warn("Receiver attempted to join non-existent channel",
			"channel_id", channelID, "remote_addr", remoteAddr)
		writeError(conn, "operation failed")
		return
	}

	// Check for existing receiver AND add the new one under a single lock
	// to prevent a TOCTOU race. Two concurrent joins must not both
	// pass the check before either adds itself.
	s.mu.Lock()
	for _, w := range s.waiters[channelID] {
		if !w.sender {
			s.mu.Unlock()
			s.logger.Warn("Receiver already registered for channel — rejecting duplicate join",
				"channel_id", channelID, "remote_addr", remoteAddr)
			writeError(conn, "operation failed")
			return
		}
	}

	// Find sender and send MsgReady while holding the lock so handleAllocate
	// cannot write to the same connection concurrently.
	var senderConn *websocket.Conn
	for _, w := range s.waiters[channelID] {
		if w.sender {
			senderConn = w.conn
			break
		}
	}
	if senderConn != nil {
		senderConn.WriteJSON(Message{Type: MsgReady, ChannelID: channelID})
	}

	// Send MsgOK to the receiver BEFORE adding it to waiters. If we add
	// the receiver first, the sender's relay (running in a separate goroutine)
	// can find it and forward a MsgBlob before MsgOK is written. The client's
	// Join() would then read the MsgBlob instead of MsgOK and fail.
	host, _, _ := net.SplitHostPort(remoteAddr)
	respMap := publicIPResponse(host)
	payload, _ := json.Marshal(respMap)
	conn.WriteJSON(Message{Type: MsgOK, ChannelID: channelID, Payload: payload})

	// Now add the receiver to waiters so the relay can forward blobs.
	wsc := &wsConn{conn: conn, sender: false}
	s.waiters[channelID] = append(s.waiters[channelID], wsc)
	s.mu.Unlock()

	if senderConn != nil {
		s.logger.Debug("Sent ready signal to sender", "channel_id", channelID)
	}

	s.logger.Info("Receiver joined channel",
		"channel_id", channelID,
		"public_ipv4", respMap["public_ipv4"],
		"public_ipv6", respMap["public_ipv6"])

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
		var peer *wsConn
		updated := conns[:0]
		for _, w := range conns {
			if w.conn == conn {
				continue
			}
			updated = append(updated, w)
			peer = w
		}
		if len(updated) == 0 {
			delete(s.waiters, channelID)
			s.logger.Debug("All peers disconnected — channel removed", "channel_id", channelID)
		} else {
			s.waiters[channelID] = updated
		}
		s.mu.Unlock()

		if peer != nil {
			s.logger.Debug("Closing peer connection — peer disconnected from relay",
				"channel_id", channelID, "role", role)
			peer.conn.Close()
		}

		s.logger.Debug("Relay loop ended", "channel_id", channelID, "role", role)
	}()

	blobCount := 0
	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			s.logger.Debug("Relay connection closed", "channel_id", channelID, "role", role, "reason", "remote side closed the connection")
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
					writeError(conn, "handshake data store failed: channel terminated")
					return
				}
				writeError(conn, "handshake data store failed")
				return
			}
			// Forward blob to peer
			s.mu.Lock()
			var peerConn *websocket.Conn
			for _, w := range s.waiters[channelID] {
				if w.sender != isSender {
					peerConn = w.conn
					break
				}
			}
			s.mu.Unlock()

			var forwarded bool
			if peerConn != nil {
				if err := peerConn.WriteJSON(Message{
					Type:      MsgBlob,
					ChannelID: channelID,
					Payload:   msg.Payload,
				}); err != nil {
					s.logger.Error("Failed to forward blob to peer", "channel_id", channelID, "err", err)
				} else {
					forwarded = true
				}
			}
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

// purgeExpiredWaiters closes and removes all waiter connections for the given
// expired channel IDs. This ensures stale waiters do not block channel reuse
// after the store entry has expired.
func (s *Server) purgeExpiredWaiters(expiredIDs []uint16) {
	s.mu.Lock()
	var toClose []*websocket.Conn
	for _, id := range expiredIDs {
		conns, ok := s.waiters[id]
		if !ok {
			continue
		}
		delete(s.waiters, id)
		for _, w := range conns {
			toClose = append(toClose, w.conn)
		}
	}
	s.mu.Unlock()
	for _, c := range toClose {
		c.Close()
	}
	if len(toClose) > 0 {
		s.logger.Debug("Purged expired waiters", "count", len(toClose))
	}
}

// dropChannel closes all peer connections for channelID, sends them a final
// error, and purges the channel from the store. It is safe to call even if the
// channel has already been removed.
func (s *Server) dropChannel(channelID uint16) {
	s.mu.Lock()
	conns := s.waiters[channelID]
	delete(s.waiters, channelID)
	// Write the error to each peer while holding the lock so that no other
	// goroutine (e.g. the peer's relay loop) writes to the same connection
	// concurrently. Gorilla WebSocket panics on concurrent writes.
	for _, w := range conns {
		_ = w.conn.WriteJSON(Message{Type: MsgError, Error: "channel terminated: CPace failure limit exceeded"})
	}
	s.mu.Unlock()

	for _, w := range conns {
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

// publicIPResponse builds the allocate/join response payload map,
// including an address-family-specific key so the client can distinguish
// IPv4 from IPv6 without re-parsing.
//
// The server always knows the remote address of the client's WebSocket
// connection. This function classifies it as IPv4 or IPv6 and populates
// the corresponding key. If parsing fails (e.g. hostname or IPv6 zone ID),
// it falls back to a family guess — the key is never silently omitted.
func publicIPResponse(host string) map[string]string {
	resp := map[string]string{"public_ip": host}
	if host == "" {
		return resp
	}
	// Strip IPv6 zone ID (e.g. "fe80::1%eth0" -> "fe80::1") because
	// net.ParseIP does not handle zone/scope IDs.
	clean := host
	if idx := strings.IndexByte(host, '%'); idx >= 0 {
		clean = host[:idx]
	}
	if ip := net.ParseIP(clean); ip != nil {
		if ip.To4() != nil {
			resp["public_ipv4"] = host
		} else {
			resp["public_ipv6"] = host
		}
	} else {
		// Hostname or unparseable address — assume IPv4 as a safe default
		// so the caller always gets at least one populated family key.
		resp["public_ipv4"] = host
	}
	return resp
}

func writeError(conn *websocket.Conn, msg string) {
	if err := conn.WriteJSON(Message{Type: MsgError, Error: msg}); err != nil {
		slog.Debug("Could not send error response to WebSocket client — client may have disconnected", "err", err)
	}
}
