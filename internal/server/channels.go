// Channel allocation and join handling over the WebSocket relay.

package server

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

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
