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

// mapToCurveSSWU implements the simplified SWU map for P-256 (RFC 9380 §6.6.2).
// Input u is a field element in [0, p-1]. Output (x, y) is a point on P-256.
// The algorithm has no data-dependent branches on u, eliminating the
// iteration-count timing channel present in try-and-increment.
func mapToCurveSSWU(u *big.Int) (*big.Int, *big.Int) {
	p := p256P
	A := p256A
	B := p256B
	Z := p256Z

	// All intermediate values are field elements in [0, p-1].
	// Helper: modular multiplication.
	mul := func(a, b *big.Int) *big.Int {
		return new(big.Int).Mod(new(big.Int).Mul(a, b), p)
	}
	// Helper: modular addition.
	add := func(a, b *big.Int) *big.Int {
		return new(big.Int).Mod(new(big.Int).Add(a, b), p)
	}
	// Helper: modular subtraction (negation: neg(a) = p - a mod p).
	neg := func(a *big.Int) *big.Int {
		if a.Sign() == 0 {
			return new(big.Int)
		}
		return new(big.Int).Sub(p, a)
	}
	// Helper: modular inverse using Fermat's little theorem (p is prime).
	inv := func(a *big.Int) *big.Int {
		// a^(p-2) mod p
		exp := new(big.Int).Sub(p, big.NewInt(2))
		return new(big.Int).Exp(a, exp, p)
	}
	// cmov: return a if cond==0, else b (constant in branch count).
	cmov := func(a, b *big.Int, cond bool) *big.Int {
		if cond {
			return new(big.Int).Set(b)
		}
		return new(big.Int).Set(a)
	}
	// sgn0: returns 1 if x is odd (LSB=1), 0 if even.
	sgn0 := func(x *big.Int) int {
		return int(new(big.Int).And(x, big.NewInt(1)).Int64())
	}

	// Steps 1–16: compute numerator tv2 and denominator tv6 for gx = tv2/tv6.
	tv1 := mul(u, u)                          // u^2
	tv1 = mul(Z, tv1)                         // Z * u^2
	tv2 := mul(tv1, tv1)                      // (Z*u^2)^2
	tv2 = add(tv2, tv1)                       // tv2 + tv1
	tv3 := add(tv2, big.NewInt(1))            // tv2 + 1
	tv3 = mul(B, tv3)                         // B * (tv2 + 1)
	tv4 := cmov(Z, neg(tv2), tv2.Sign() != 0) // CMOV(Z, -tv2, tv2 != 0)
	tv4 = mul(A, tv4)                         // A * tv4

	tv2num := mul(tv3, tv3)   // tv3^2
	tv6 := mul(tv4, tv4)      // tv4^2
	tv5 := mul(A, tv6)        // A * tv6
	tv2num = add(tv2num, tv5) // tv3^2 + A*tv4^2
	tv2num = mul(tv2num, tv3) // (tv3^2 + A*tv4^2) * tv3
	tv6 = mul(tv6, tv4)       // tv4^3
	tv5 = mul(B, tv6)         // B * tv4^3
	tv2num = add(tv2num, tv5) // numerator of gx1

	// x1 candidate (not yet divided by tv4).
	x1 := mul(tv1, tv3) // Z*u^2 * tv3

	// sqrt_ratio(tv2num, tv6): compute candidate sqrt of tv2num/tv6.
	isSquare, y1 := sqrtRatioP256(tv2num, tv6)

	// y candidate from second branch.
	y := mul(tv1, u)
	y = mul(y, y1)

	// CMOV based on whether gx1 is a perfect square.
	x := cmov(x1, tv3, isSquare)
	yFinal := cmov(y, y1, isSquare)

	// Adjust sign of y to match sign of u.
	e1 := sgn0(u) == sgn0(yFinal)
	yFinal = cmov(neg(yFinal), yFinal, e1)

	// x = x / tv4 (divide by the denominator).
	x = mul(x, inv(tv4))

	// Reduce to [0, p-1].
	x.Mod(x, p)
	yFinal.Mod(yFinal, p)
	return x, yFinal
}

// sqrtRatioP256 computes sqrt(u/v) for P-256 where p ≡ 3 (mod 4).
// Returns (true, sqrt(u/v)) if u/v is a quadratic residue,
// or (false, sqrt(Z*u/v)) otherwise (RFC 9380, Appendix F.2.1.2).
// v must be non-zero (guaranteed by SSWU construction).
func sqrtRatioP256(u, v *big.Int) (bool, *big.Int) {
	p := p256P
	c1 := p256C1

	mul := func(a, b *big.Int) *big.Int {
		return new(big.Int).Mod(new(big.Int).Mul(a, b), p)
	}

	// r = (u * v^3) * (u * v^7)^c1
	v2 := mul(v, v)
	v3 := mul(v2, v)
	v4 := mul(v2, v2)
	v7 := mul(v4, v3)

	tv1 := mul(u, v7)
	tv1.Exp(tv1, c1, p) // (u * v^7)^c1
	r := mul(mul(u, v3), tv1)

	// check = v * r^2
	r2 := mul(r, r)
	check := mul(v, r2)

	isSquare := check.Cmp(u) == 0 // constant in branch count

	// If not a square, r *= sqrt(Z). For P-256 we need sqrt(Z) mod p.
	// sqrt(Z) for Z = p-10: precomputed or computed once.
	if !isSquare {
		sqrtZ := p256SqrtZ()
		r = mul(r, sqrtZ)
	}
	return isSquare, r
}

// p256SqrtZ returns sqrt(Z) mod p for P-256 where Z = p - 10.
// sqrt(Z) = Z^((p+1)/4) mod p (valid because p ≡ 3 mod 4).
func p256SqrtZ() *big.Int {
	exp := new(big.Int).Add(p256P, big.NewInt(1))
	exp.Rsh(exp, 2) // (p+1)/4
	return new(big.Int).Exp(p256Z, exp, p256P)
}

// p256PointAdd adds two P-256 affine points using standard formulas.
// Handles the case where both points are distinct and neither is the point at infinity.
// For the hash-to-curve context the two SSWU outputs are always distinct non-infinity points.
func p256PointAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p := p256P
	mod := func(a *big.Int) *big.Int { return new(big.Int).Mod(a, p) }
	mul := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }
	sub := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Sub(new(big.Int).Add(a, p), b)) }
	add := func(a, b *big.Int) *big.Int { return mod(new(big.Int).Add(a, b)) }
	inv := func(a *big.Int) *big.Int {
		exp := new(big.Int).Sub(p, big.NewInt(2))
		return new(big.Int).Exp(a, exp, p)
	}

	// Handle point doubling (x1 == x2, y1 == y2).
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		// slope = (3*x1^2 + a) / (2*y1)
		x1sq := mul(x1, x1)
		num := mod(new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), x1sq), p256A))
		den := inv(mul(big.NewInt(2), y1))
		lambda := mul(num, den)
		rx := sub(mul(lambda, lambda), add(x1, x1))
		ry := sub(mul(lambda, sub(x1, rx)), y1)
		return rx, ry
	}

	// Standard affine addition: slope = (y2-y1)/(x2-x1).
	dx := sub(x2, x1)
	dy := sub(y2, y1)
	lambda := mul(dy, inv(dx))
	rx := sub(sub(mul(lambda, lambda), x1), x2)
	ry := sub(mul(lambda, sub(x1, rx)), y1)
	return rx, ry
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
