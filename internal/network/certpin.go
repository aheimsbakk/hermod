// Shared TLS VerifyPeerCertificate callback for signaling-server SPKI
// pinning. Used by both the WebSocket dialer and the /cert fetcher so the
// error text and comparison stay identical in both paths.

package network

import (
	"crypto/subtle"
	"crypto/x509"
	"fmt"
)

// newServerCertPinner returns a VerifyPeerCertificate callback that compares
// the server's SPKI fingerprint against pinnedFingerprint using a
// constant-time comparison. host is used in the guidance message so the user
// can re-pin with the exact URL they dialed.
func newServerCertPinner(pinnedFingerprint, host string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("server did not present a TLS certificate")
		}
		got := PubKeyFingerprint(rawCerts[0])
		if got == "" {
			return fmt.Errorf("could not read the server certificate")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(pinnedFingerprint)) != 1 {
			return fmt.Errorf("the server's public key does not match the pinned fingerprint. The server may have been restarted with a new certificate. Run 'hermod trust %s' to update the fingerprint", host)
		}
		return nil
	}
}
