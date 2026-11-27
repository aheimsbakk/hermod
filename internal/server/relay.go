// Blob relay loop and channel teardown.

package server

import (
	"github.com/gorilla/websocket"
)

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
			s.recordFailureAndDrop(channelID)
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
	_ = s.store.DeleteChannel(channelID)
	s.mu.Unlock()

	for _, w := range conns {
		w.conn.Close()
	}
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
