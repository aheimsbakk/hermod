// CPace PAKE per RFC 9496 over P-256. Point and scalar helpers shared
// with the hash-to-curve code live here because CPace is their only caller.

package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// p256Order is the order of the P-256 curve (number of points on the group).
// Used by randScalar to generate a valid scalar in [1, n-1].
var p256Order, _ = new(big.Int).SetString(
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

// recoverYOnP256 computes the y-coordinate for a given x on P-256 so that
// (x, y) satisfies y² = x³ - 3x + b (mod p). Since p ≡ 3 (mod 4), the
// square root is y = (y²)^((p+1)/4) mod p. Either root is valid for ECDH
// (shared secret is the x-coordinate only), and both parties use the same
// recovery algorithm, so the protocol is consistent.
func recoverYOnP256(x *big.Int) *big.Int {
	p := p256P
	// y² = x³ - 3x + b (mod p)
	x3 := new(big.Int).Exp(x, big.NewInt(3), p)
	ax := new(big.Int).Mod(new(big.Int).Mul(p256A, x), p)
	y2 := new(big.Int).Add(new(big.Int).Add(x3, ax), p256B)
	y2.Mod(y2, p)
	// sqrt: y = y2^((p+1)/4) mod p
	exp := new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2) // (p+1)/4
	return new(big.Int).Exp(y2, exp, p)
}

// --- CPace (RFC 9496 simplified over P-256) ---

// CPaceSession holds ephemeral state for one side of the CPace exchange.
type CPaceSession struct {
	scalar  []byte // 32-byte big-endian scalar
	pubMsg  []byte // 65-byte uncompressed point: 0x04 || X || Y
	role    string // "sender" or "receiver" — used for ISK transcript ordering
	sharedK []byte // set after Finish
}

// cpacePointSize is the byte length of an uncompressed P-256 point.
const cpacePointSize = 65

// CPaceInit creates a new CPace initiator message from the password.
// channelID is the transfer channel integer used as a domain separator.
// role must be "sender" or "receiver"; it is bound into the ISK derivation
// to provide role-based domain separation per RFC 9496 intent.
// Returns the session and the public message (65 bytes) to send to the peer.
func CPaceInit(password string, channelID uint16, role string) (*CPaceSession, []byte, error) {
	// Generator = hash-to-curve(password || channelID || "sender:receiver")
	// Both parties use the same combined role domain so the generator is shared.
	gx, gy, err := cpaceGenerator(password, channelID)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace generator: %w", err)
	}

	// Generate ephemeral scalar y
	scalar, err := randScalar(p256Order)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace scalar: %w", err)
	}

	// Y = scalar * G_password using crypto/ecdh (constant-time, stdlib only).
	curve := ecdh.P256()
	privKey, err := curve.NewPrivateKey(scalar.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("cpace private key: %w", err)
	}
	genBytes := marshalPoint(gx, gy)
	genKey, err := curve.NewPublicKey(genBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace generator public key: %w", err)
	}
	sharedX, err := privKey.ECDH(genKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace scalar mult: %w", err)
	}
	Yx := new(big.Int).SetBytes(sharedX)
	Yy := recoverYOnP256(Yx)

	pubMsg := marshalPoint(Yx, Yy)

	return &CPaceSession{
		scalar: scalar.Bytes(),
		pubMsg: pubMsg,
		role:   role,
	}, pubMsg, nil
}

// CPaceFinish completes the CPace exchange given the peer's public message (65 bytes).
// Returns the 32-byte shared secret K.
// The ISK is derived as SHA-256(iskX || pubSender || pubReceiver), where the
// role stored in the session determines which public message belongs to sender
// and which to receiver. This binds the role into the shared secret and
// prevents cross-role composition attacks.
func (s *CPaceSession) CPaceFinish(peerPub []byte) ([]byte, error) {
	if len(peerPub) != cpacePointSize || peerPub[0] != 0x04 {
		return nil, errors.New("invalid peer public message: must be a 65-byte uncompressed P-256 point")
	}

	// Parse and validate the peer point using ecdh (validates on-curve).
	curve := ecdh.P256()
	peerKey, err := curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("cpace finish invalid peer point: %w", err)
	}

	// ISK_x = scalar * peerPub using constant-time ECDH.
	// ECDH returns the x-coordinate of the point, which is what we need.
	privKey, err := curve.NewPrivateKey(s.scalar)
	if err != nil {
		return nil, fmt.Errorf("cpace finish private key: %w", err)
	}
	iskXBytes, err := privKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("cpace finish ecdh: %w", err)
	}
	iskX := new(big.Int).SetBytes(iskXBytes)

	// Build role-ordered transcript: iskX || pubSender || pubReceiver.
	// Both sides resolve sender/receiver the same way using their stored role,
	// so the byte sequence — and thus the derived key — is identical.
	var senderPub, receiverPub []byte
	if s.role == "sender" {
		senderPub, receiverPub = s.pubMsg, peerPub
	} else {
		senderPub, receiverPub = peerPub, s.pubMsg
	}
	transcript := make([]byte, 0, 32+cpacePointSize+cpacePointSize)
	transcript = append(transcript, padTo32(iskX)...)
	transcript = append(transcript, senderPub...)
	transcript = append(transcript, receiverPub...)

	h := sha256.Sum256(transcript)
	k := h[:]
	s.sharedK = k
	return k, nil
}

// cpaceGenerator hashes the password + channelID to a P-256 point using
// the P256_XMD:SHA-256_SSWU_RO_ suite (RFC 9380).
// The domain separation tag embeds the combined role tag "sender:receiver"
// so the generator is role-aware while remaining identical for both peers.
// Unlike the former try-and-increment approach, SSWU always produces a valid
// point in a single, fixed-length computation, eliminating the loop-count
// timing side channel.
func cpaceGenerator(password string, channelID uint16) (*big.Int, *big.Int, error) {
	dst := p256DST(password, channelID)
	// Input message is the fixed role tag; the password is in the DST.
	msg := []byte("sender:receiver")
	pt, err := hashToCurveP256(msg, dst)
	if err != nil {
		return nil, nil, fmt.Errorf("cpace hash-to-curve: %w", err)
	}
	// pt is a 65-byte uncompressed point: 0x04 || X(32) || Y(32).
	x := new(big.Int).SetBytes(pt[1:33])
	y := new(big.Int).SetBytes(pt[33:65])
	return x, y, nil
}

func padTo32(n *big.Int) []byte {
	// FillBytes always produces exactly 32 bytes. For P-256 scalars and
	// coordinates the value is guaranteed to fit in 32 bytes; if it does
	// not the panic is correct (crypto code must not silently truncate).
	out := make([]byte, 32)
	n.FillBytes(out)
	return out
}

func marshalPoint(x, y *big.Int) []byte {
	pt := make([]byte, 65)
	pt[0] = 0x04
	copy(pt[1:33], padTo32(x))
	copy(pt[33:], padTo32(y))
	return pt
}

// randScalar generates a uniformly random scalar in [1, n-1] using rejection
// sampling (L-03). A 32-byte random value is accepted only if it falls in
// [1, n-1]; otherwise a new value is drawn. This is unbiased and correctly
// communicates the algorithm's intent, unlike the former modular-reduction
// approach whose retry loop could never fire.
func randScalar(n *big.Int) (*big.Int, error) {
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			return k, nil
		}
	}
}
