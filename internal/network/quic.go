// QUIC transport: dial and listen with mutual SPKI pinning.

package network

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// --- QUIC flow control constants (receiver-side credits, not pre-allocated buffers) ---

// QUIC flow control windows sized for 10 Gbit/s BDP (12.5 MB at 10 Gbit/s / 10 ms).
// These are receiver-side credits — memory is consumed only when data actually
// arrives at the receiver, so the same values are safe on 10 Mbit/s links too.
const (
	quicInitialStreamReceiveWindow     = 64 << 20  // 64 MiB
	quicMaxStreamReceiveWindow         = 256 << 20 // 256 MiB
	quicInitialConnectionReceiveWindow = 64 << 20  // 64 MiB
	quicMaxConnectionReceiveWindow     = 256 << 20 // 256 MiB
)

// DialQUIC establishes a QUIC connection to peerAddr using the muxed conn.
// peerCertHash is the expected SHA-256 fingerprint (hex) of the peer's TLS certificate.
func DialQUIC(ctx context.Context, mux *packetMux, peerAddr *net.UDPAddr, baseTLS *tls.Config, peerCertHash string) (*quic.Conn, error) {
	tlsCfg := baseTLS.Clone()
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.VerifyPeerCertificate = makeCertPinner(peerCertHash)
	tlsCfg.NextProtos = []string{"hermod-p2p"}

	transport := &quic.Transport{
		Conn: &muxedConn{mux: mux},
	}
	conn, err := transport.Dial(ctx, peerAddr, tlsCfg, &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                5 * time.Second,
		InitialStreamReceiveWindow:     quicInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicInitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     quicMaxConnectionReceiveWindow,
	})
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}
	return conn, nil
}

// ListenQUIC starts a QUIC listener on the muxed conn.
func ListenQUIC(mux *packetMux, cert tls.Certificate, baseTLS *tls.Config, peerCertHash string) (*quic.Listener, error) {
	tlsCfg := baseTLS.Clone()
	tlsCfg.Certificates = []tls.Certificate{cert}
	tlsCfg.ClientAuth = tls.RequireAnyClientCert
	tlsCfg.InsecureSkipVerify = true
	tlsCfg.VerifyPeerCertificate = makeCertPinner(peerCertHash)
	tlsCfg.NextProtos = []string{"hermod-p2p"}

	transport := &quic.Transport{
		Conn: &muxedConn{mux: mux},
	}
	ln, err := transport.Listen(tlsCfg, &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                5 * time.Second,
		InitialStreamReceiveWindow:     quicInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicInitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     quicMaxConnectionReceiveWindow,
	})
	if err != nil {
		return nil, fmt.Errorf("QUIC listen: %w", err)
	}
	return ln, nil
}

// PubKeyFingerprint computes the SHA-256 fingerprint of the Subject Public Key
// Info (SPKI) of a DER-encoded X.509 certificate. Unlike CertFingerprint, this
// value stays the same when the certificate is renewed with the same key pair,
// so clients do not need to re-pin after a cert rotation.
func PubKeyFingerprint(certDER []byte) string {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ""
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// makeCertPinner returns a VerifyPeerCertificate function that enforces SPKI
// (Subject Public Key Info) hash pinning. Unlike certificate DER pinning, SPKI
// pinning survives certificate renewal with the same key pair.
// The fingerprint comparison uses crypto/subtle.ConstantTimeCompare to prevent
// timing side-channel attacks.
func makeCertPinner(expectedHex string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("peer did not present a TLS certificate")
		}
		got := PubKeyFingerprint(rawCerts[0])
		if got == "" {
			return fmt.Errorf("could not read the peer certificate. The connection was aborted because the peer presented an invalid certificate")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(expectedHex)) != 1 {
			return fmt.Errorf("peer identity verification failed: the public key does not match the expected fingerprint. This may mean the transfer code was used by someone else. Verify the code and try again")
		}
		return nil
	}
}
