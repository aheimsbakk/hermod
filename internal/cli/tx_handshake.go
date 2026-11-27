// Package cli: sender-side hybrid key exchange (CPace + X25519 + ML-KEM-768)
// and encrypted endpoint bundle exchange, relayed through the signaling server.

package cli

import (
	"fmt"
	"net"

	"github.com/hermod/hermod/internal/crypto"
	"github.com/hermod/hermod/internal/network"
)

// handshakeInput carries the session state both handshake directions need:
// the signaling client pair (raw conn for closing, context-bound for reads),
// the transfer password, and the locally discovered network addresses.
type handshakeInput struct {
	sig            *network.SignalingClient
	sigRaw         *network.SignalingClient
	password       string
	channelID      uint16
	verify         bool
	myFingerprint  string
	localAddr      *net.UDPAddr
	discoveredAddr *net.UDPAddr
	publicIPV4     string
	publicIPV6     string
	ipFamily       network.IPFamily
}

// senderHandshake performs the sender half of the hybrid handshake: blob 1
// (CPace point + X25519 pub), blob 2 receive, key derivation, blob 3
// (ML-KEM ciphertext + sealed bundle), and blob 4 receive. The signaling
// WebSocket is closed once the bundles have been exchanged.
//
// Returns the peer's endpoint bundle, the hybrid blob key, and the merged
// verify flag (true if either side requires SAS verification).
func senderHandshake(in handshakeInput) (network.EndpointBundle, []byte, bool, error) {
	// CPace init
	logDebug("initialising CPace PAKE handshake", "role", "sender")
	cpaceSession, myPubMsg, err := crypto.CPaceInit(in.password, in.channelID, "sender")
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("initialize CPace handshake: %w", err)
	}

	// Generate X25519 key pair for hybrid KEM
	logDebug("generating X25519 key pair for hybrid KEM")
	x25519Priv, x25519Pub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("generate X25519 key pair: %w", err)
	}

	// Wait for receiver to join
	logInfo("Waiting for receiver to join the channel")
	if err := in.sig.WaitReady(); err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("wait for receiver: %w", err)
	}
	logInfo("Receiver joined the channel")

	// Send blob 1: CPace public message + X25519 public key (binary)
	logDebug("sending hybrid handshake blob 1 (CPace + X25519 pub) to peer via relay")
	blob1 := network.SenderHandshakeBlob(myPubMsg, x25519Pub)
	if err := in.sig.SendBlob(in.channelID, blob1); err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("send hybrid handshake blob 1: %w", err)
	}

	// Receive blob 2: receiver's CPace + X25519 pub + ML-KEM enc key (binary)
	logDebug("waiting for receiver hybrid handshake blob 2 from relay")
	blob2, err := in.sig.RecvBlob()
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("receive hybrid handshake blob 2: %w", err)
	}
	peerCPacePub, peerX25519Pub, peerMLKEMEncapKey, err := network.ParseReceiverHandshakeBlob(blob2)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("parse receiver handshake blob: %w", err)
	}
	logDebug("receiver handshake blob received and parsed")

	// Finish CPace to get shared secret
	logDebug("completing CPace handshake to derive shared key")
	kClassical, err := cpaceSession.CPaceFinish(peerCPacePub)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("complete CPace handshake: %w", err)
	}
	logInfo("PAKE handshake complete — shared key established")

	// X25519 ECDH shared secret
	logDebug("computing X25519 ECDH shared secret")
	peerX25519Key, err := crypto.NewX25519PubFromBytes(peerX25519Pub)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("parse peer X25519 public key: %w", err)
	}
	ssX25519, err := crypto.ECDHX25519(x25519Priv, peerX25519Key)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("X25519 ECDH: %w", err)
	}

	// ML-KEM encapsulation
	logDebug("performing ML-KEM-768 encapsulation")
	peerMLKEMKey, err := crypto.NewEncapsulationKey768Bytes(peerMLKEMEncapKey)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("parse peer ML-KEM encapsulation key: %w", err)
	}
	ssMLKEM, kemCt := crypto.EncapsulateMLKEM(peerMLKEMKey)

	// Derive hybrid blob key
	logDebug("deriving hybrid blob key from CPace + X25519 + ML-KEM")
	hybridKey := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)

	localV4, localV6, publicEPV4, publicEPV6 := collectEndpoints(
		in.localAddr.Port, in.discoveredAddr, in.publicIPV4, in.publicIPV6, in.ipFamily)

	bundle := network.EndpointBundle{
		LocalEndpointsV4:  localV4,
		LocalEndpointsV6:  localV6,
		PublicEndpointV4:  publicEPV4,
		PublicEndpointV6:  publicEPV6,
		PubKeyFingerprint: in.myFingerprint,
		RequireVerify:     in.verify,
	}
	bundleBytes, err := network.EncodeEndpointBundle(bundle)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("encode endpoint bundle: %w", err)
	}
	encBundle, err := crypto.SealAAD(hybridKey, channelIDAad(in.channelID), bundleBytes)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("encrypt endpoint bundle: %w", err)
	}
	logDebug("endpoint bundle encrypted, sending blob 3 (KEM ct + enc bundle) via relay")
	blob3 := network.SenderBundleBlob(kemCt, encBundle)
	if err := in.sig.SendBlob(in.channelID, blob3); err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("send blob 3 (KEM ct + bundle): %w", err)
	}

	// Receive peer's bundle
	logDebug("waiting for receiver endpoint bundle blob 4 from relay")
	encPeerBundle, err := in.sig.RecvBlob()
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("receive endpoint bundle blob 4 from peer: %w", err)
	}
	// Signaling work is done — close the WebSocket to free server resources.
	in.sigRaw.Close()
	peerBundleBytes, err := crypto.OpenAAD(hybridKey, channelIDAad(in.channelID), encPeerBundle)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("decrypt peer endpoint bundle: %w", err)
	}
	peerBundle, err := network.DecodeEndpointBundle(peerBundleBytes)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("decode peer endpoint bundle: %w", err)
	}
	logDebug("receiver endpoint bundle received",
		"public_v4", peerBundle.PublicEndpointV4,
		"public_v6", peerBundle.PublicEndpointV6,
		"local_v4_count", len(peerBundle.LocalEndpointsV4),
		"local_v6_count", len(peerBundle.LocalEndpointsV6),
		"require_verify", peerBundle.RequireVerify,
	)

	// Enforce verification symmetrically: if either side requires it, both must do it.
	verify := in.verify
	if !verify && peerBundle.RequireVerify {
		logInfo("Receiver requested SAS verification — enabling for this transfer")
	}
	verify = verify || peerBundle.RequireVerify

	return peerBundle, hybridKey, verify, nil
}
