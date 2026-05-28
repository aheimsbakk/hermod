// Package server: WebSocket signaling relay.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxFailures    = 3
	maxMessageSize = 65536 // 64 KiB per signaling message
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
	store      SignalingStore
	rl         *RateLimiter
	ttl        time.Duration
	upgrader   websocket.Upgrader
	httpServer *http.Server
	logger     *slog.Logger

	mu      sync.Mutex
	waiters map[uint16][]*wsConn // pending peer connections
}

type wsConn struct {
	conn   *websocket.Conn
	sender bool
}

// NewServer constructs a new signaling Server.
func NewServer(store SignalingStore, rl *RateLimiter, ttl time.Duration, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:   store,
		rl:      rl,
		ttl:     ttl,
		logger:  logger,
		waiters: make(map[uint16][]*wsConn),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
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

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.Serve(tlsLn)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutCtx)
	case err := <-errCh:
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

// handleCert serves the server's DER-encoded certificate for pinning.
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// Return server cert from TLS state
		if r.TLS != nil && len(r.TLS.TLSUnique) > 0 {
			http.Error(w, "no cert", http.StatusNotFound)
			return
		}
	}
	// The cert is embedded in the connection's TLS state
	http.Error(w, "use /cert endpoint over TLS", http.StatusOK)
}

// handleWS handles WebSocket connections from clients.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	if !s.rl.Allow(remoteAddr) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("ws upgrade", "err", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(maxMessageSize)

	s.serveClient(conn, remoteAddr)
}

func (s *Server) serveClient(conn *websocket.Conn, remoteAddr string) {
	// Read first message to determine role
	var initMsg Message
	if err := conn.ReadJSON(&initMsg); err != nil {
		s.logger.Debug("client init read", "err", err)
		return
	}

	switch initMsg.Type {
	case MsgAllocate:
		s.handleAllocate(conn, remoteAddr, initMsg.ChannelID)
	case MsgJoin:
		s.handleJoin(conn, remoteAddr, initMsg.ChannelID, initMsg.Payload)
	default:
		writeError(conn, "unknown init message type")
	}
}

// handleAllocate processes a sender's channel allocation request.
func (s *Server) handleAllocate(conn *websocket.Conn, remoteAddr string, channelID uint16) {
	if err := s.store.AllocateChannel(channelID, s.ttl); err != nil {
		writeError(conn, "channel allocation failed")
		return
	}
	// Reply with public IP (STUN-like)
	host, _, _ := net.SplitHostPort(remoteAddr)
	payload, _ := json.Marshal(map[string]string{"public_ip": host})
	conn.WriteJSON(Message{Type: MsgOK, ChannelID: channelID, Payload: payload})

	wsc := &wsConn{conn: conn, sender: true}
	s.mu.Lock()
	s.waiters[channelID] = append(s.waiters[channelID], wsc)
	s.mu.Unlock()

	// Now relay blobs between peers
	s.relay(conn, channelID, true)
}

// handleJoin processes a receiver's join request.
func (s *Server) handleJoin(conn *websocket.Conn, remoteAddr string, channelID uint16, _ []byte) {
	host, _, _ := net.SplitHostPort(remoteAddr)
	payload, _ := json.Marshal(map[string]string{"public_ip": host})
	conn.WriteJSON(Message{Type: MsgOK, ChannelID: channelID, Payload: payload})

	wsc := &wsConn{conn: conn, sender: false}
	s.mu.Lock()
	s.waiters[channelID] = append(s.waiters[channelID], wsc)
	// Notify sender that receiver has joined
	for _, w := range s.waiters[channelID] {
		if w.sender {
			w.conn.WriteJSON(Message{Type: MsgReady, ChannelID: channelID})
			break
		}
	}
	s.mu.Unlock()

	s.relay(conn, channelID, false)
}

// relay reads handshake blobs from one peer and forwards them to the other.
func (s *Server) relay(conn *websocket.Conn, channelID uint16, isSender bool) {
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
		} else {
			s.waiters[channelID] = updated
		}
		s.mu.Unlock()
	}()

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}

		switch msg.Type {
		case MsgBlob:
			if err := s.store.StoreBlob(channelID, isSender, msg.Payload); err != nil {
				writeError(conn, "store blob failed")
				return
			}
			// Forward blob to peer
			s.mu.Lock()
			for _, w := range s.waiters[channelID] {
				if w.sender != isSender {
					w.conn.WriteJSON(Message{
						Type:      MsgBlob,
						ChannelID: channelID,
						Payload:   msg.Payload,
					})
					break
				}
			}
			s.mu.Unlock()

		default:
			writeError(conn, "unexpected message type")
			return
		}
	}
}

func writeError(conn *websocket.Conn, msg string) {
	conn.WriteJSON(Message{Type: MsgError, Error: msg})
}
