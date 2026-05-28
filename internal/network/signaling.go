// Package network: signaling WebSocket client.
package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/gorilla/websocket"

	"github.com/hermod/hermod/internal/server"
)

// SignalingClient manages a WebSocket connection to the signaling server.
type SignalingClient struct {
	conn *websocket.Conn
	ctx  context.Context
}

// dialSignaling opens a WebSocket connection to serverURL, pinning the cert
// fingerprint if provided (empty = accept any cert for `trust` bootstrapping).
func dialSignaling(serverURL string, pinnedFingerprint string) (*SignalingClient, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("parse server url: %w", err)
	}
	// Convert wss:// -> https:// for dialing
	switch u.Scheme {
	case "wss":
		u.Scheme = "wss"
	case "ws":
		u.Scheme = "ws"
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	if pinnedFingerprint != "" {
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificate")
			}
			got := CertFingerprint(rawCerts[0])
			if got != pinnedFingerprint {
				return fmt.Errorf("server cert fingerprint mismatch: got %s, want %s", got, pinnedFingerprint)
			}
			return nil
		}
	}

	dialer := websocket.Dialer{
		TLSClientConfig: tlsCfg,
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

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", wsURL, err)
	}
	return &SignalingClient{conn: conn, ctx: context.Background()}, nil
}

// DialSignaling opens a WebSocket to serverURL with optional cert pinning.
func DialSignaling(serverURL, pinnedFingerprint string) (*SignalingClient, error) {
	return dialSignaling(serverURL, pinnedFingerprint)
}

// WithContext returns a copy of the client whose blocking reads are cancelled
// when ctx is done. It starts a background goroutine that, on cancellation,
// sets a past read deadline on the connection to unblock any pending Recv call.
func (c *SignalingClient) WithContext(ctx context.Context) *SignalingClient {
	child := &SignalingClient{conn: c.conn, ctx: ctx}
	go func() {
		<-ctx.Done()
		// Unblock any blocking ReadJSON by expiring the read deadline.
		_ = c.conn.SetReadDeadline(time.Unix(0, 0))
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

// Close closes the WebSocket connection.
func (c *SignalingClient) Close() error {
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
	return msg, c.ctxErr(err)
}

// Allocate sends an allocate request for channelID.
// Returns the public IP reported by the server.
func (c *SignalingClient) Allocate(channelID uint16) (string, error) {
	if err := c.Send(server.Message{Type: server.MsgAllocate, ChannelID: channelID}); err != nil {
		return "", fmt.Errorf("allocate send: %w", err)
	}
	resp, err := c.Recv()
	if err != nil {
		return "", fmt.Errorf("allocate recv: %w", err)
	}
	if resp.Type == server.MsgError {
		return "", fmt.Errorf("server error: %s", resp.Error)
	}
	var m map[string]string
	if err := json.Unmarshal(resp.Payload, &m); err == nil {
		return m["public_ip"], nil
	}
	return "", nil
}

// Join sends a join request for channelID.
// Returns the public IP reported by the server.
func (c *SignalingClient) Join(channelID uint16) (string, error) {
	if err := c.Send(server.Message{Type: server.MsgJoin, ChannelID: channelID}); err != nil {
		return "", fmt.Errorf("join send: %w", err)
	}
	resp, err := c.Recv()
	if err != nil {
		return "", fmt.Errorf("join recv: %w", err)
	}
	if resp.Type == server.MsgError {
		return "", fmt.Errorf("server error: %s", resp.Error)
	}
	var m map[string]string
	if err := json.Unmarshal(resp.Payload, &m); err == nil {
		return m["public_ip"], nil
	}
	return "", nil
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
			// receiver joined — sender waits for Ready before sending blob
			continue
		case server.MsgError:
			return nil, fmt.Errorf("relay error: %s", msg.Error)
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

// FetchServerFingerprint connects to serverURL with no cert verification and
// returns the server's certificate SHA-256 fingerprint.
func FetchServerFingerprint(serverURL string) (string, error) {
	client, err := dialSignaling(serverURL, "")
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	// Extract fingerprint from the underlying TLS connection
	// We need to get it from the handshake — reconnect with custom verifier
	var fp string
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) > 0 {
				fp = CertFingerprint(rawCerts[0])
			}
			return nil
		},
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}
	wsURL := u.String()
	if wsURL[len(wsURL)-3:] != "/ws" {
		wsURL += "/ws"
	}
	dialer := websocket.Dialer{TLSClientConfig: tlsCfg}
	conn2, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return "", fmt.Errorf("dial for fingerprint: %w", err)
	}
	conn2.Close()
	if fp == "" {
		return "", fmt.Errorf("could not extract certificate fingerprint")
	}
	return fp, nil
}
