// Package network: signaling WebSocket client.
package network

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
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
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server did not present a TLS certificate")
			}
			got := PubKeyFingerprint(rawCerts[0])
			if got == "" {
				return fmt.Errorf("could not read the server certificate")
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(pinnedFingerprint)) != 1 {
				return fmt.Errorf("the server's public key does not match the pinned fingerprint. The server may have been restarted with a new certificate. Run 'hermod trust %s' to update the fingerprint", u.Host)
			}
			return nil
		}
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

// FetchServerFingerprint fetches the server's TLS certificate via the HTTPS
// /cert endpoint and returns its SHA-256 Subject Public Key Info (SPKI)
// fingerprint. SPKI fingerprints persist across certificate renewals with the
// same key pair, so clients do not need to re-pin after a cert rotation.
//
// When pinnedFingerprint is non-empty, the SPKI fingerprint is verified against
// this value during the TLS handshake. The connection fails if the fingerprint
// does not match. When pinnedFingerprint is empty, the TLS connection is made
// without certificate verification (TOFU). Only use this mode over a trusted
// network (VPN, LAN, or when you can verify the fingerprint out-of-band).
//
// When family is not IPFamilyAny, DNS resolution and TCP connections are
// restricted to that IP protocol family.
// The request is cancelled when ctx is done.
func FetchServerFingerprint(ctx context.Context, serverURL string, pinnedFingerprint string, family IPFamily) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	// Convert wss:// → https:// for the HTTP request.
	u.Scheme = "https"
	certURL := u.String()
	// Strip any trailing /ws path and append /cert.
	if len(certURL) >= 3 && certURL[len(certURL)-3:] == "/ws" {
		certURL = certURL[:len(certURL)-3]
	}
	certURL += "/cert"

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if pinnedFingerprint != "" {
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server did not present a TLS certificate")
			}
			got := PubKeyFingerprint(rawCerts[0])
			if got == "" {
				return fmt.Errorf("could not read the server certificate")
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(pinnedFingerprint)) != 1 {
				return fmt.Errorf("the server's public key does not match the pinned fingerprint. The server may have been restarted with a new certificate. Run 'hermod trust %s' to update the fingerprint", u.Host)
			}
			return nil
		}
	}
	// No VerifyPeerCertificate when pinnedFingerprint is empty — TOFU mode.
	// The caller is responsible for ensuring they run this over a trusted network.

	transport := &http.Transport{TLSClientConfig: tlsCfg}
	// Restrict DNS resolution and TCP connections to the requested IP family.
	// Use the provided context so cancellation propagates to the TCP dial (M3).
	if family == IPFamilyV4 {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
		}
	} else if family == IPFamilyV6 {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp6", addr)
		}
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, certURL, nil)
	if err != nil {
		return "", fmt.Errorf("create cert request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch cert from %s: %w", certURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("certificate endpoint returned %s", resp.Status)
	}

	// M2: limit certificate response to 8 KB (a valid PEM cert is at most ~2 KB).
	certPEM, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", fmt.Errorf("read cert response: %w", err)
	}
	if len(certPEM) >= 8192 {
		return "", fmt.Errorf("certificate response exceeds maximum size")
	}
	if len(certPEM) == 0 {
		return "", fmt.Errorf("empty certificate response")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("certificate endpoint did not return a valid PEM certificate")
	}

	return PubKeyFingerprint(block.Bytes), nil
}
