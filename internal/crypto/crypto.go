// Package crypto implements cryptographic primitives for hermod.
//
// CPace is implemented per RFC 9496 using P-256 (NIST curve) with
// hash-to-curve via the P256_XMD:SHA-256_SSWU_RO_ suite (RFC 9380).
// SSWU produces a valid curve point in a single, fixed-length computation
// with no data-dependent loop iterations, eliminating the timing side channel
// present in try-and-increment. The role ("sender"/"receiver") is bound into
// the ISK derivation via a role-ordered transcript, providing domain separation
// per RFC 9496 intent.
// AES-256-GCM is used for signaling payload encryption keyed by the CPace
// shared secret.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// --- Hybrid KEM (X25519 + ML-KEM-768) ---

// GenerateX25519KeyPair generates an ephemeral X25519 key pair.
// Returns the private key and the 32-byte public key.
func GenerateX25519KeyPair() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// ECDHX25519 computes the X25519 ECDH shared secret.
func ECDHX25519(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(pub)
}

// NewX25519PubFromBytes parses a 32-byte X25519 public key.
func NewX25519PubFromBytes(data []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(data)
}

// MLKEMReceiverKey holds the receiver-side ML-KEM-768 key pair.
type MLKEMReceiverKey struct {
	DecapKey *mlkem.DecapsulationKey768
	EncapKey *mlkem.EncapsulationKey768
}

// GenerateMLKEMReceiverKey generates an ML-KEM-768 key pair for the receiver.
func GenerateMLKEMReceiverKey() (*MLKEMReceiverKey, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("mlkem keygen: %w", err)
	}
	return &MLKEMReceiverKey{
		DecapKey: dk,
		EncapKey: dk.EncapsulationKey(),
	}, nil
}

// EncapKeyBytes returns the 1184-byte ML-KEM-768 encapsulation key.
func (k *MLKEMReceiverKey) EncapKeyBytes() []byte {
	return k.EncapKey.Bytes()
}

// NewEncapsulationKey768Bytes parses a 1184-byte ML-KEM-768 encapsulation key.
func NewEncapsulationKey768Bytes(data []byte) (*mlkem.EncapsulationKey768, error) {
	return mlkem.NewEncapsulationKey768(data)
}

// EncapsulateMLKEM encapsulates a shared secret with the peer's encapsulation key.
// Returns (sharedKey [32]byte, ciphertext [1088]byte).
// NOTE: Encapsulate return order is (sharedKey, ciphertext) despite the Go doc.
func EncapsulateMLKEM(ek *mlkem.EncapsulationKey768) ([]byte, []byte) {
	return ek.Encapsulate()
}

// DecapsulateMLKEM recovers the shared secret from a ciphertext.
func DecapsulateMLKEM(dk *mlkem.DecapsulationKey768, ciphertext []byte) ([]byte, error) {
	return dk.Decapsulate(ciphertext)
}

// DeriveHybridBlobKey combines the three pillars into a single 32-byte key.
// The combiner is a simple SHA-256 concatenation:
//
//	hybridKey = SHA-256(kClassical || ssX25519 || ssMLKEM)
//
// This is a split combiner — security is at least as strong as the strongest
// component. If P-256 falls to quantum cryptanalysis, ML-KEM-768 still
// protects the bundle. If ML-KEM is broken, CPace + X25519 still protects it.
func DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM []byte) []byte {
	h := sha256.New()
	h.Write(kClassical)
	h.Write(ssX25519)
	h.Write(ssMLKEM)
	return h.Sum(nil)
}

// --- AES-256-GCM ---

// SealAAD encrypts plaintext with key (must be 32 bytes) using AES-256-GCM,
// binding aad as Additional Authenticated Data. The AAD is authenticated but
// not included in the ciphertext. Pass nil for no AAD.
// Returns nonce || ciphertext || tag.
func SealAAD(key, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, plaintext, aad)
	return ct, nil
}

// OpenAAD decrypts a blob produced by SealAAD, verifying the provided AAD.
// Pass nil aad when no AAD was used during encryption.
func OpenAAD(key, aad, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("decrypt: blob too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], aad)
}
