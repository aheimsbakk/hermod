// Fetches the signaling server TLS certificate over HTTPS for pinning.

package network

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

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
		tlsCfg.VerifyPeerCertificate = newServerCertPinner(pinnedFingerprint, u.Host)
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
