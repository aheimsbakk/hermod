// Package network: signaling WebSocket client.
package network

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/hermod/hermod/internal/server"
)

// maxMessageSize limits WebSocket message size on the client side to match
// the server-side limit. This prevents a compromised relay from forcing
// unbounded memory allocation on the client.
const maxMessageSize = 65536 // 64 KiB

// SignalingClient manages a WebSocket connection to the signaling server.
type SignalingClient struct {
	conn      *websocket.Conn
	ctx       context.Context
	done      chan struct{} // closed by Close() to unblock WithContext goroutines (L-08)
	closeOnce sync.Once
}

// dialSignaling opens a WebSocket connection to serverURL, pinning the cert
// fingerprint if provided (empty = accept any cert for `trust` bootstrapping).
// When family is not IPFamilyAny, the TCP connection is restricted to addresses
// from that IP protocol family only.
// The dial is cancelled when ctx is done; HandshakeTimeout is set to 15s.
func dialSignaling(ctx context.Context, serverURL string, pinnedFingerprint string, family IPFamily) (*SignalingClient, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse server url: %w", err)
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "wss"
	case "ws":
		return nil, fmt.Errorf("plaintext WebSocket (ws://) is not allowed by default; use wss://")
	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", u.Scheme)
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	if pinnedFingerprint != "" {
		tlsCfg.VerifyPeerCertificate = newServerCertPinner(pinnedFingerprint, u.Host)
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 15 * time.Second, // M1: bound the WebSocket handshake
	}
	// Restrict DNS resolution and TCP connections to the requested IP family.
	// Use the provided context so cancellation propagates to the TCP dial (M3).
	if family == IPFamilyV4 {
		dialer.NetDial = func(n, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
		}
	} else if family == IPFamilyV6 {
		dialer.NetDial = func(n, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp6", addr)
		}
	}
	wsURL := u.String()
	// Append /ws path if not present
	if wsURL[len(wsURL)-3:] != "/ws" {
		if wsURL[len(wsURL)-1] != '/' {
			wsURL += "/ws"
		} else {
			wsURL += "ws"
		}
	}

	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("WebSocket dial on %s: %w", wsURL, err)
	}
	conn.SetReadLimit(maxMessageSize)
	return &SignalingClient{conn: conn, ctx: ctx, done: make(chan struct{})}, nil
}

// DialSignalingWithFamily opens a WebSocket to serverURL with optional cert pinning
// and restricts DNS resolution and TCP connections to the given IP family.
func DialSignalingWithFamily(ctx context.Context, serverURL, pinnedFingerprint string, family IPFamily) (*SignalingClient, error) {
	return dialSignaling(ctx, serverURL, pinnedFingerprint, family)
}

// WithContext returns a copy of the client whose blocking reads are cancelled
// when ctx is done. It starts a background goroutine that, on cancellation,
// sets a past read deadline on the connection to unblock any pending Recv call.
// The goroutine also exits when the client is closed via Close(), preventing
// goroutine leaks when a non-cancellable context (e.g. context.Background()) is
// passed (L-08).
func (c *SignalingClient) WithContext(ctx context.Context) *SignalingClient {
	child := &SignalingClient{conn: c.conn, ctx: ctx, done: c.done}
	go func() {
		select {
		case <-ctx.Done():
			// Unblock any blocking ReadJSON by expiring the read deadline.
			_ = c.conn.SetReadDeadline(time.Unix(0, 0))
		case <-c.done:
			// Client was closed — exit to avoid goroutine leak.
		}
	}()
	return child
}

// ctxErr returns ctx.Err() if the context is done, otherwise returns err.
// Use this to surface cancellation instead of a raw net timeout error.
func (c *SignalingClient) ctxErr(err error) error {
	if err != nil && c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	return err
}

// Close closes the WebSocket connection and signals any WithContext goroutines
// to exit, preventing goroutine leaks (L-08).
func (c *SignalingClient) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() { close(c.done) })
	return c.conn.Close()
}

// Send writes a message to the server.
func (c *SignalingClient) Send(msg server.Message) error {
	return c.conn.WriteJSON(msg)
}

// Recv reads the next message from the server.
func (c *SignalingClient) Recv() (server.Message, error) {
	var msg server.Message
	err := c.conn.ReadJSON(&msg)
	if err != nil {
		return msg, c.ctxErr(err)
	}
	if len(msg.Payload) > maxMessageSize {
		return msg, fmt.Errorf("server message payload exceeds maximum size (%d bytes)", maxMessageSize)
	}
	return msg, nil
}

// Allocate sends an allocate request for channelID.
// Returns the public IPs (v4 and v6) reported by the server.
// One or both may be empty if the server does not advertise both families.
func (c *SignalingClient) Allocate(channelID uint16) (publicV4, publicV6 string, err error) {
	if err := c.Send(server.Message{Type: server.MsgAllocate, ChannelID: channelID}); err != nil {
		return "", "", fmt.Errorf("allocate send: %w", err)
	}
	// The server may reply with either MsgOK (the normal response) or MsgReady
	// (if the receiver already joined before handleAllocate could reply).
	// Handle both to avoid a non-deterministic hang with -cover (L-09).
	for {
		resp, err := c.Recv()
		if err != nil {
			return "", "", fmt.Errorf("allocate recv: %w", err)
		}
		switch resp.Type {
		case server.MsgOK:
			var m map[string]string
			if err := json.Unmarshal(resp.Payload, &m); err != nil {
				return "", "", fmt.Errorf("allocate decode response: %w", err)
			}
			return m["public_ipv4"], m["public_ipv6"], nil
		case server.MsgReady:
			// Receiver already joined — Allocate is effectively done.
			// Return empty IPs; the sender will fall back to local endpoints.
			return "", "", nil
		case server.MsgError:
			return "", "", fmt.Errorf("server error: %s", resp.Error)
		}
	}
}

// Join sends a join request for channelID.
// Returns the public IPs (v4 and v6) reported by the server.
// One or both may be empty if the server does not advertise both families.
func (c *SignalingClient) Join(channelID uint16) (publicV4, publicV6 string, err error) {
	if err := c.Send(server.Message{Type: server.MsgJoin, ChannelID: channelID}); err != nil {
		return "", "", fmt.Errorf("join send: %w", err)
	}
	resp, err := c.Recv()
	if err != nil {
		return "", "", fmt.Errorf("join recv: %w", err)
	}
	if resp.Type == server.MsgError {
		return "", "", fmt.Errorf("server error: %s", resp.Error)
	}
	var m map[string]string
	if err := json.Unmarshal(resp.Payload, &m); err != nil {
		return "", "", fmt.Errorf("join decode response: %w", err)
	}
	return m["public_ipv4"], m["public_ipv6"], nil
}

// SendBlob sends an encrypted blob payload to the peer via the relay.
func (c *SignalingClient) SendBlob(channelID uint16, blob []byte) error {
	return c.Send(server.Message{Type: server.MsgBlob, ChannelID: channelID, Payload: blob})
}

// RecvBlob waits for a blob message from the relay.
func (c *SignalingClient) RecvBlob() ([]byte, error) {
	for {
		msg, err := c.Recv()
		if err != nil {
			return nil, err
		}
		switch msg.Type {
		case server.MsgBlob:
			return msg.Payload, nil
		case server.MsgReady:
			continue
		case server.MsgError:
			return nil, fmt.Errorf("relay error: %s", msg.Error)
		default:
		}
	}
}

// WaitReady waits for the MsgReady signal (sent to sender when receiver joins).
func (c *SignalingClient) WaitReady() error {
	for {
		msg, err := c.Recv()
		if err != nil {
			return err
		}
		if msg.Type == server.MsgReady {
			return nil
		}
		if msg.Type == server.MsgError {
			return fmt.Errorf("relay error: %s", msg.Error)
		}
	}
}
