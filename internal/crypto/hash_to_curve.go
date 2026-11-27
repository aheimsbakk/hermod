// Package-level file: constant-time hash-to-curve for P-256.
//
// Implements the P256_XMD:SHA-256_SSWU_RO_ suite from RFC 9380.
// Replaces try-and-increment to eliminate the loop-count timing channel.
// All field arithmetic uses math/big, which is not instruction-level
// constant-time, but the algorithm has NO data-dependent conditional branches
// on secret inputs — the same code path executes for every input.
package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// p256Field holds the P-256 prime and common constants used by SSWU.
var (
	// p is the P-256 field prime.
	p256P, _ = new(big.Int).SetString(
		"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)

	// a = -3 mod p (P-256 curve coefficient).
	p256A = new(big.Int).Sub(p256P, big.NewInt(3))

	// b is the P-256 curve coefficient B.
	p256B, _ = new(big.Int).SetString(
		"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

	// z = -10 mod p — the SSWU Z constant for P-256 (RFC 9380 §8.2).
	p256Z = new(big.Int).Sub(p256P, big.NewInt(10))

	// c1 = (p - 3) / 4, used for sqrt in p ≡ 3 (mod 4).
	p256C1 = new(big.Int).Rsh(new(big.Int).Sub(p256P, big.NewInt(3)), 2)

	// (p256Two reserved for sgn0 if needed in future)
)

// hashToCurveP256 hashes msg to a P-256 point using the
// P256_XMD:SHA-256_SSWU_RO_ suite (RFC 9380).
// dst is the domain separation tag (must be non-empty).
// Returns the uncompressed 65-byte point (0x04 || X || Y).
func hashToCurveP256(msg []byte, dst []byte) ([]byte, error) {
	if len(dst) == 0 {
		return nil, errors.New("hash to curve: domain separation tag (DST) must not be empty")
	}
	// hash_to_field produces 2 field elements (random-oracle variant hashes twice).
	u, err := hashToFieldP256(msg, dst, 2)
	if err != nil {
		return nil, err
	}
	// Map each field element to a curve point and add them.
	q0x, q0y := mapToCurveSSWU(u[0])
	q1x, q1y := mapToCurveSSWU(u[1])

	// Add q0 + q1 using standard P-256 point addition (handles all cases).
	rx, ry := p256PointAdd(q0x, q0y, q1x, q1y)

	// Encode as uncompressed point.
	pt := make([]byte, 65)
	pt[0] = 0x04
	copy(pt[1:33], padTo32(rx))
	copy(pt[33:], padTo32(ry))
	return pt, nil
}

// hashToFieldP256 implements hash_to_field for P-256 (RFC 9380 §5.2).
// count is the number of field elements to produce (1 or 2 for RO variant).
func hashToFieldP256(msg, dst []byte, count int) ([]*big.Int, error) {
	const L = 48 // ceil((log2(p) + k) / 8) = ceil((256 + 128) / 8) = 48 for 128-bit security
	pseudo, err := expandMessageXMD(msg, dst, count*L)
	if err != nil {
		return nil, err
	}
	out := make([]*big.Int, count)
	for i := range out {
		chunk := pseudo[i*L : (i+1)*L]
		e := new(big.Int).SetBytes(chunk)
		e.Mod(e, p256P)
		out[i] = e
	}
	return out, nil
}

// expandMessageXMD implements expand_message_xmd using SHA-256 (RFC 9380 §5.3.1).
// lenInBytes is the total number of output bytes requested.
func expandMessageXMD(msg, dst []byte, lenInBytes int) ([]byte, error) {
	h := sha256.New()
	bLen := h.Size()  // 32 for SHA-256
	bBits := bLen * 8 // 256

	// ell = ceil(lenInBytes / b_len)
	ell := (lenInBytes + bLen - 1) / bLen
	if ell > 255 {
		return nil, errors.New("expand message: requested length exceeds maximum")
	}
	if lenInBytes > 65535 {
		return nil, errors.New("expand message: requested output exceeds 65535 bytes")
	}
	if len(dst) > 255 {
		return nil, errors.New("expand message: domain separation tag (DST) exceeds maximum length")
	}

	// DST_prime = DST || I2OSP(len(DST), 1)
	dstPrime := append(dst, byte(len(dst))) //nolint:gocritic // intentional slice extension

	// Z_pad = I2OSP(0, r_in_bytes) — r_in_bytes = block size of SHA-256 = 64
	_ = bBits
	const rInBytes = 64
	zPad := make([]byte, rInBytes)

	// l_i_b_str = I2OSP(len_in_bytes, 2)
	libStr := []byte{byte(lenInBytes >> 8), byte(lenInBytes)}

	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	h.Reset()
	h.Write(zPad)
	h.Write(msg)
	h.Write(libStr)
	h.Write([]byte{0})
	h.Write(dstPrime)
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	h.Write(b0)
	h.Write([]byte{1})
	h.Write(dstPrime)
	bi := h.Sum(nil)

	out := make([]byte, 0, ell*bLen)
	out = append(out, bi...)

	prev := bi
	for i := 2; i <= ell; i++ {
		// b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime)
		xored := make([]byte, bLen)
		for j := range xored {
			xored[j] = b0[j] ^ prev[j]
		}
		h.Reset()
		h.Write(xored)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		bi = h.Sum(nil)
		out = append(out, bi...)
		prev = bi
	}
	return out[:lenInBytes], nil
}

// p256DST returns the domain separation tag for the CPace generator hash.
// It encodes the password, channelID, and fixed suite identifier so that
// the output point is unique to this session.
func p256DST(password string, channelID uint16) []byte {
	// DST format: "hermod-cpace-v1:" || channelID_be16 || ":" || password
	// Kept short; RFC 9380 §3.1 allows up to 255 bytes.
	chanBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(chanBytes, channelID)
	dst := make([]byte, 0, 18+len(password))
	dst = append(dst, []byte("hermod-cpace-v1:")...)
	dst = append(dst, chanBytes...)
	dst = append(dst, ':')
	dst = append(dst, []byte(password)...)
	if len(dst) > 255 {
		// RFC 9380 §5.3.3: DSTs longer than 255 bytes MUST be encoded as
		// SHA-256("H2C-OVERSIZE-DST-" || DST). Truncation is NOT permitted
		// because two DSTs sharing the same first 255 bytes would collide.
		h := sha256.New()
		h.Write([]byte("H2C-OVERSIZE-DST-"))
		h.Write(dst)
		dst = h.Sum(nil)
	}
	return dst
}
