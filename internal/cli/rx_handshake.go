// Package cli: receiver-side hybrid key exchange (CPace + X25519 + ML-KEM-768)
// and encrypted endpoint bundle exchange, relayed through the signaling server.

package cli

import (
	"fmt"

	"github.com/hermod/hermod/internal/crypto"
	"github.com/hermod/hermod/internal/network"
)

// receiverHandshake performs the receiver half of the hybrid handshake: blob 1
// receive, blob 2 (CPace point + X25519 pub + ML-KEM encapsulation key) send,
// blob 3 receive with ML-KEM decapsulation, key derivation, and blob 4
// (sealed bundle) send. The signaling WebSocket is closed once the bundles
// have been exchanged.
//
// Returns the sender's endpoint bundle, the hybrid blob key, and the merged
// verify flag (true if either side requires SAS verification).
func receiverHandshake(in handshakeInput) (network.EndpointBundle, []byte, bool, error) {
	// CPace init (receiver role)
	logDebug("initialising CPace PAKE handshake", "role", "receiver")
	cpaceSession, myPubMsg, err := crypto.CPaceInit(in.password, in.channelID, "receiver")
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("initialize CPace handshake: %w", err)
	}

	// Generate X25519 key pair + ML-KEM receiver key for hybrid KEM
	logDebug("generating X25519 + ML-KEM-768 key pairs")
	x25519Priv, x25519Pub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("generate X25519 key pair: %w", err)
	}
	mlkemKeys, err := crypto.GenerateMLKEMReceiverKey()
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("generate ML-KEM key pair: %w", err)
	}

	// Receive sender's blob 1: CPace + X25519 pub
	logDebug("waiting for sender hybrid handshake blob 1 from relay")
	blob1, err := in.sig.RecvBlob()
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("receive sender handshake blob 1: %w", err)
	}
	peerCPacePub, peerX25519Pub, err := network.ParseSenderHandshakeBlob(blob1)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("parse sender handshake blob: %w", err)
	}
	logDebug("sender handshake blob 1 received and parsed")

	// Finish CPace
	logDebug("completing CPace handshake to derive shared key")
	kClassical, err := cpaceSession.CPaceFinish(peerCPacePub)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("complete CPace handshake: %w", err)
	}
	logInfo("PAKE handshake complete — shared key established")

	// X25519 ECDH shared secret (before sending blob 2, so we can send immediately)
	logDebug("computing X25519 ECDH shared secret")
	peerX25519Key, err := crypto.NewX25519PubFromBytes(peerX25519Pub)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("parse sender X25519 public key: %w", err)
	}
	ssX25519, err := crypto.ECDHX25519(x25519Priv, peerX25519Key)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("X25519 ECDH: %w", err)
	}

	// Send blob 2: CPace + X25519 pub + ML-KEM enc key (binary)
	logDebug("sending hybrid handshake blob 2 (CPace + X25519 + MLKEM ek) via relay")
	blob2 := network.ReceiverHandshakeBlob(myPubMsg, x25519Pub, mlkemKeys.EncapKeyBytes())
	if err := in.sig.SendBlob(in.channelID, blob2); err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("send hybrid handshake blob 2: %w", err)
	}

	// Receive blob 3: KEM ciphertext + encrypted sender bundle
	logDebug("waiting for sender bundle blob 3 (KEM ct + enc bundle) from relay")
	blob3, err := in.sig.RecvBlob()
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("receive sender bundle blob 3: %w", err)
	}
	kemCt, encSenderBundle, err := network.ParseSenderBundleBlob(blob3)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("parse sender bundle blob: %w", err)
	}

	// ML-KEM decapsulation
	logDebug("decapsulating ML-KEM-768 shared secret")
	ssMLKEM, err := crypto.DecapsulateMLKEM(mlkemKeys.DecapKey, kemCt)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("ML-KEM decapsulation: %w", err)
	}

	// Derive hybrid blob key
	logDebug("deriving hybrid blob key from CPace + X25519 + ML-KEM")
	hybridKey := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)

	// Decrypt sender's bundle with hybrid key
	senderBundleBytes, err := crypto.OpenAAD(hybridKey, channelIDAad(in.channelID), encSenderBundle)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("decrypt sender endpoint bundle: %w", err)
	}
	senderBundle, err := network.DecodeEndpointBundle(senderBundleBytes)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("decode sender endpoint bundle: %w", err)
	}
	logDebug("sender endpoint bundle received",
		"public_v4", senderBundle.PublicEndpointV4,
		"public_v6", senderBundle.PublicEndpointV6,
		"local_v4_count", len(senderBundle.LocalEndpointsV4),
		"local_v6_count", len(senderBundle.LocalEndpointsV6),
		"require_verify", senderBundle.RequireVerify,
	)

	// Enforce verification symmetrically: if either side requires it, both must do it.
	verify := in.verify
	if !verify && senderBundle.RequireVerify {
		logInfo("Sender requested SAS verification — enabling for this transfer")
	}
	verify = verify || senderBundle.RequireVerify

	// Send our bundle (dual-stack)
	localV4, localV6, publicEPV4, publicEPV6 := collectEndpoints(
		in.localAddr.Port, in.discoveredAddr, in.publicIPV4, in.publicIPV6, in.ipFamily)

	myBundle := network.EndpointBundle{
		LocalEndpointsV4:  localV4,
		LocalEndpointsV6:  localV6,
		PublicEndpointV4:  publicEPV4,
		PublicEndpointV6:  publicEPV6,
		PubKeyFingerprint: in.myFingerprint,
		RequireVerify:     verify,
	}
	myBundleBytes, err := network.EncodeEndpointBundle(myBundle)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("encode endpoint bundle: %w", err)
	}
	encMyBundle, err := crypto.SealAAD(hybridKey, channelIDAad(in.channelID), myBundleBytes)
	if err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("encrypt endpoint bundle: %w", err)
	}
	logDebug("endpoint bundle encrypted, sending blob 4 (enc bundle) to sender via relay")
	if err := in.sig.SendBlob(in.channelID, encMyBundle); err != nil {
		return network.EndpointBundle{}, nil, false, fmt.Errorf("send endpoint bundle blob 4: %w", err)
	}
	// Signaling work is done — close the WebSocket to free server resources.
	in.sigRaw.Close()

	return senderBundle, hybridKey, verify, nil
}
