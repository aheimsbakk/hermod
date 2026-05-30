package crypto

// RFC 9380 compliance tests.
// Test vectors from Appendix J.1.1 (P256_XMD:SHA-256_SSWU_RO_) and
// Appendix K.1 (expand_message_xmd SHA-256).
//
// These tests verify each layer of the implementation independently:
//   expand_message_xmd → hash_to_field → map_to_curve → hash_to_curve

import (
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// rfcDST is the test DST used in RFC 9380 Appendix J.1.1.
const rfcDST = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"

// hexNoSpace strips whitespace and decodes a hex string.
func hexNoSpace(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\t", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex: " + err.Error())
	}
	return b
}

func hexBigInt(s string) *big.Int {
	return new(big.Int).SetBytes(hexNoSpace(s))
}

// ─────────────────────────────────────────────────────────────────────────────
// expand_message_xmd — RFC 9380 Appendix K.1, first vector (msg="", len=32)
// ─────────────────────────────────────────────────────────────────────────────

func TestExpandMessageXMD_RFC_K1(t *testing.T) {
	t.Parallel()
	dst := []byte("QUUX-V01-CS02-with-expander-SHA256-128")
	want := hexNoSpace("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")

	got, err := expandMessageXMD([]byte{}, dst, 32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("expand_message_xmd mismatch\n got:  %x\n want: %x", got, want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// hash_to_field — RFC 9380 Appendix J.1.1, msg="" vector
// u[0] and u[1] must match the RFC values exactly.
// ─────────────────────────────────────────────────────────────────────────────

func TestHashToFieldP256_RFC_EmptyMsg(t *testing.T) {
	t.Parallel()
	wantU0 := hexBigInt("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009")
	wantU1 := hexBigInt("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a")

	got, err := hashToFieldP256([]byte{}, []byte(rfcDST), 2)
	if err != nil {
		t.Fatalf("hashToFieldP256: %v", err)
	}
	if got[0].Cmp(wantU0) != 0 {
		t.Errorf("u[0] mismatch\n got:  %x\n want: %x", got[0], wantU0)
	}
	if got[1].Cmp(wantU1) != 0 {
		t.Errorf("u[1] mismatch\n got:  %x\n want: %x", got[1], wantU1)
	}
}

func TestHashToFieldP256_RFC_AbcMsg(t *testing.T) {
	t.Parallel()
	wantU0 := hexBigInt("afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1")
	wantU1 := hexBigInt("379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0")

	got, err := hashToFieldP256([]byte("abc"), []byte(rfcDST), 2)
	if err != nil {
		t.Fatalf("hashToFieldP256: %v", err)
	}
	if got[0].Cmp(wantU0) != 0 {
		t.Errorf("u[0] mismatch\n got:  %x\n want: %x", got[0], wantU0)
	}
	if got[1].Cmp(wantU1) != 0 {
		t.Errorf("u[1] mismatch\n got:  %x\n want: %x", got[1], wantU1)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// map_to_curve — RFC 9380 Appendix J.1.1, msg="" vector
// Q0 and Q1 must match the RFC values exactly.
// ─────────────────────────────────────────────────────────────────────────────

func TestMapToCurveSSWU_RFC_EmptyMsg(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256()

	u0 := hexBigInt("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009")
	u1 := hexBigInt("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a")

	wantQ0x := hexBigInt("ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5")
	wantQ0y := hexBigInt("dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1")
	wantQ1x := hexBigInt("51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5")
	wantQ1y := hexBigInt("b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac")

	q0x, q0y := mapToCurveSSWU(u0)
	q1x, q1y := mapToCurveSSWU(u1)

	if q0x.Cmp(wantQ0x) != 0 {
		t.Errorf("Q0.x mismatch\n got:  %x\n want: %x", q0x, wantQ0x)
	}
	if q0y.Cmp(wantQ0y) != 0 {
		t.Errorf("Q0.y mismatch\n got:  %x\n want: %x", q0y, wantQ0y)
	}
	if q1x.Cmp(wantQ1x) != 0 {
		t.Errorf("Q1.x mismatch\n got:  %x\n want: %x", q1x, wantQ1x)
	}
	if q1y.Cmp(wantQ1y) != 0 {
		t.Errorf("Q1.y mismatch\n got:  %x\n want: %x", q1y, wantQ1y)
	}

	// Also verify both points are on the curve.
	if !curve.IsOnCurve(q0x, q0y) {
		t.Error("Q0 not on P-256")
	}
	if !curve.IsOnCurve(q1x, q1y) {
		t.Error("Q1 not on P-256")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// hash_to_curve — RFC 9380 Appendix J.1.1, all five msg vectors.
// The final P.x, P.y must match exactly.
// ─────────────────────────────────────────────────────────────────────────────

type hashToCurveVector struct {
	msg string
	px  string
	py  string
}

var rfcHashToCurveVectors = []hashToCurveVector{
	{
		msg: "",
		px:  "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
		py:  "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
	},
	{
		msg: "abc",
		px:  "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
		py:  "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
	},
	{
		msg: "abcdef0123456789",
		px:  "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
		py:  "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
	},
	{
		// q128_ prefix: 128-character repeated-q string.
		msg: "q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
		px:  "4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
		py:  "98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
	},
	{
		// a512_ prefix: "a512_" + 512 a's = 517 chars total.
		msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		px:  "457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
		py:  "ecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
	},
}

func TestHashToCurveP256_RFC_Vectors(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256()
	dst := []byte(rfcDST)

	for _, tc := range rfcHashToCurveVectors {
		tc := tc
		t.Run("msg="+tc.msg, func(t *testing.T) {
			t.Parallel()
			wantX := hexBigInt(tc.px)
			wantY := hexBigInt(tc.py)

			pt, err := hashToCurveP256([]byte(tc.msg), dst)
			if err != nil {
				t.Fatalf("hashToCurveP256: %v", err)
			}
			gotX := new(big.Int).SetBytes(pt[1:33])
			gotY := new(big.Int).SetBytes(pt[33:65])

			if !curve.IsOnCurve(gotX, gotY) {
				t.Fatal("output point not on P-256")
			}
			if gotX.Cmp(wantX) != 0 {
				t.Errorf("P.x mismatch\n got:  %x\n want: %x", gotX, wantX)
			}
			if gotY.Cmp(wantY) != 0 {
				t.Errorf("P.y mismatch\n got:  %x\n want: %x", gotY, wantY)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sqrtRatioP256 contract verification.
//
// RFC 9380 F.2.1.2 specifies:
//   isQR=true  → y = sqrt(u/v),  i.e.  v*y^2 = u
//   isQR=false → y = sqrt(Z*u/v), i.e.  v*y^2 = Z*u
//
// This test verifies both branches for a range of (u, v) pairs.
// ─────────────────────────────────────────────────────────────────────────────

func TestSqrtRatioP256_Contract(t *testing.T) {
	t.Parallel()
	p := p256P
	Z := p256Z

	mul := func(a, b *big.Int) *big.Int {
		return new(big.Int).Mod(new(big.Int).Mul(a, b), p)
	}

	// Legendre symbol: returns 1 if x is a QR, -1 if not, 0 if x==0.
	legendre := func(x *big.Int) int {
		exp := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1) // (p-1)/2
		r := new(big.Int).Exp(x, exp, p)
		if r.Sign() == 0 {
			return 0
		}
		if r.Cmp(big.NewInt(1)) == 0 {
			return 1
		}
		return -1 // r == p-1
	}

	testCases := []struct{ u, v *big.Int }{
		{big.NewInt(1), big.NewInt(1)},
		{big.NewInt(2), big.NewInt(3)},
		{big.NewInt(7), big.NewInt(11)},
		{big.NewInt(100), big.NewInt(200)},
		// Use RFC u values (known field elements).
		{
			hexBigInt("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009"),
			hexBigInt("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a"),
		},
	}

	for _, tc := range testCases {
		u, v := tc.u, tc.v
		isQR, y := sqrtRatioP256(u, v)

		// Compute v * y^2 mod p.
		vy2 := mul(v, mul(y, y))

		if isQR {
			// Contract: v * y^2 == u.
			if vy2.Cmp(u) != 0 {
				t.Errorf("isQR=true but v*y^2 != u (u=%x, v=%x)", u, v)
			}
			// Cross-check: u/v must actually be a QR.
			inv := new(big.Int).ModInverse(v, p)
			ratio := mul(u, inv)
			if legendre(ratio) == -1 {
				t.Errorf("isQR reported true but u/v is not a QR (u=%x, v=%x)", u, v)
			}
		} else {
			// Contract: v * y^2 == Z * u.
			Zu := mul(Z, u)
			if vy2.Cmp(Zu) != 0 {
				t.Errorf("isQR=false but v*y^2 != Z*u (u=%x, v=%x)\n got v*y^2: %x\n want Z*u: %x", u, v, vy2, Zu)
			}
			// Cross-check: u/v must actually be a non-QR.
			inv := new(big.Int).ModInverse(v, p)
			ratio := mul(u, inv)
			if legendre(ratio) == 1 {
				t.Errorf("isQR reported false but u/v is a QR (u=%x, v=%x)", u, v)
			}
		}
	}
}
