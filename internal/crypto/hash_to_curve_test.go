package crypto

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"
)

// TestHashToCurveP256Deterministic checks that the same input always maps to
// the same point (RFC 9380 requires a deterministic function).
func TestHashToCurveP256Deterministic(t *testing.T) {
	t.Parallel()
	dst := []byte("hermod-cpace-v1-test")
	msg := []byte("sender:receiver")

	pt1, err := hashToCurveP256(msg, dst)
	if err != nil {
		t.Fatalf("hashToCurveP256 first call: %v", err)
	}
	pt2, err := hashToCurveP256(msg, dst)
	if err != nil {
		t.Fatalf("hashToCurveP256 second call: %v", err)
	}
	if !bytes.Equal(pt1, pt2) {
		t.Error("same input produced different points (not deterministic)")
	}
}

// TestHashToCurveP256OnCurve verifies the output point lies on P-256.
func TestHashToCurveP256OnCurve(t *testing.T) {
	t.Parallel()
	dst := []byte("hermod-cpace-v1-test")
	curve := elliptic.P256()

	testCases := []string{
		"",
		"hello",
		"sender:receiver",
		"a very long password string with unicode: αβγδ",
	}
	for _, tc := range testCases {
		pt, err := hashToCurveP256([]byte(tc), dst)
		if err != nil {
			t.Errorf("msg=%q: unexpected error: %v", tc, err)
			continue
		}
		if len(pt) != 65 || pt[0] != 0x04 {
			t.Errorf("msg=%q: bad point encoding", tc)
			continue
		}
		x := new(big.Int).SetBytes(pt[1:33])
		y := new(big.Int).SetBytes(pt[33:65])
		if !curve.IsOnCurve(x, y) {
			t.Errorf("msg=%q: point not on P-256", tc)
		}
	}
}

// TestHashToCurveP256DSTSeparation verifies different DSTs produce different points.
func TestHashToCurveP256DSTSeparation(t *testing.T) {
	t.Parallel()
	msg := []byte("sender:receiver")

	pt1, err := hashToCurveP256(msg, []byte("dst-a"))
	if err != nil {
		t.Fatalf("DST-a: %v", err)
	}
	pt2, err := hashToCurveP256(msg, []byte("dst-b"))
	if err != nil {
		t.Fatalf("DST-b: %v", err)
	}
	if bytes.Equal(pt1, pt2) {
		t.Error("different DSTs produced the same point (DST separation broken)")
	}
}

// TestHashToCurveP256MsgSeparation verifies different messages produce different points.
func TestHashToCurveP256MsgSeparation(t *testing.T) {
	t.Parallel()
	dst := []byte("hermod-cpace-v1-test")

	pt1, err := hashToCurveP256([]byte("password-a"), dst)
	if err != nil {
		t.Fatalf("msg-a: %v", err)
	}
	pt2, err := hashToCurveP256([]byte("password-b"), dst)
	if err != nil {
		t.Fatalf("msg-b: %v", err)
	}
	if bytes.Equal(pt1, pt2) {
		t.Error("different messages produced the same point")
	}
}

// TestExpandMessageXMDLength verifies the output length matches the request.
func TestExpandMessageXMDLength(t *testing.T) {
	t.Parallel()
	for _, length := range []int{32, 48, 64, 96} {
		out, err := expandMessageXMD([]byte("test"), []byte("dst"), length)
		if err != nil {
			t.Errorf("len=%d: error: %v", length, err)
			continue
		}
		if len(out) != length {
			t.Errorf("len=%d: got %d bytes", length, len(out))
		}
	}
}

// TestExpandMessageXMDDistinct verifies different inputs produce different outputs.
func TestExpandMessageXMDDistinct(t *testing.T) {
	t.Parallel()
	a, _ := expandMessageXMD([]byte("msg-a"), []byte("dst"), 48)
	b, _ := expandMessageXMD([]byte("msg-b"), []byte("dst"), 48)
	if bytes.Equal(a, b) {
		t.Error("different messages produced identical XMD output")
	}
}

// TestMapToCurveSSWUOnCurve verifies the SSWU map always outputs a valid P-256 point.
func TestMapToCurveSSWUOnCurve(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256()

	// Test several field elements including edge cases.
	inputs := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(100),
		new(big.Int).Sub(p256P, big.NewInt(1)), // p-1
	}
	for _, u := range inputs {
		x, y := mapToCurveSSWU(u)
		if !curve.IsOnCurve(x, y) {
			t.Errorf("u=%v: SSWU output not on P-256", u)
		}
	}
}

// TestP256DSTEncoding verifies the DST encodes channelID and password distinctly.
func TestP256DSTEncoding(t *testing.T) {
	t.Parallel()
	d1 := p256DST("pass", 1)
	d2 := p256DST("pass", 2)
	d3 := p256DST("other", 1)

	if bytes.Equal(d1, d2) {
		t.Error("different channelIDs produced the same DST")
	}
	if bytes.Equal(d1, d3) {
		t.Error("different passwords produced the same DST")
	}
}
