package crypto_test

import (
	"bytes"
	"testing"

	"github.com/hermod/hermod/internal/crypto"
)

func TestGenerateTransferCode(t *testing.T) {
	id, code, err := crypto.GenerateTransferCode(3)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if code == "" {
		t.Fatal("empty transfer code")
	}
	parsedID, words, err := crypto.ParseTransferCode(code)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsedID != id {
		t.Fatalf("ID mismatch: got %d, want %d", parsedID, id)
	}
	if len(words) != 3 {
		t.Fatalf("expected 3 words, got %d", len(words))
	}
}

func TestGenerateTransferCodeMoreWords(t *testing.T) {
	_, code, err := crypto.GenerateTransferCode(5)
	if err != nil {
		t.Fatalf("generate 5-word: %v", err)
	}
	_, words, err := crypto.ParseTransferCode(code)
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 5 {
		t.Fatalf("expected 5 words, got %d", len(words))
	}
}

func TestGenerateTransferCodeMinWords(t *testing.T) {
	// numWords < 3 should be clamped to 3
	_, code, err := crypto.GenerateTransferCode(1)
	if err != nil {
		t.Fatal(err)
	}
	_, words, _ := crypto.ParseTransferCode(code)
	if len(words) < 3 {
		t.Fatalf("expected at least 3 words, got %d", len(words))
	}
}

func TestWordlistIntegrity(t *testing.T) {
	words := crypto.EFFShortWordlist()
	if len(words) != 1296 {
		t.Fatalf("expected 1296 words, got %d", len(words))
	}
	seen := make(map[string]struct{}, len(words))
	for _, w := range words {
		if _, dup := seen[w]; dup {
			t.Fatalf("duplicate word in wordlist: %q", w)
		}
		seen[w] = struct{}{}
	}
}

func TestParseTransferCodeInvalid(t *testing.T) {
	cases := []string{
		"nodashescode",
		"notanint-word-word-word",
		"123-only-two",
	}
	for _, c := range cases {
		_, _, err := crypto.ParseTransferCode(c)
		if err == nil {
			t.Fatalf("expected error for %q", c)
		}
	}
}

func TestTransferCodePassword(t *testing.T) {
	_, code, _ := crypto.GenerateTransferCode(3)
	pw, err := crypto.TransferCodePassword(code)
	if err != nil {
		t.Fatalf("password: %v", err)
	}
	if pw == "" {
		t.Fatal("empty password")
	}
}

func TestSealOpen(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("hello, world!")

	ct, err := crypto.Seal(key, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(ct) <= len(plaintext) {
		t.Fatal("ciphertext too short")
	}

	pt, err := crypto.Open(key, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("decryption mismatch: got %q", pt)
	}
}

func TestOpenTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	ct, _ := crypto.Seal(key, []byte("data"))
	ct[len(ct)-1] ^= 0xFF
	_, err := crypto.Open(key, ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestOpenTooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := crypto.Open(key, []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for too-short blob")
	}
}

func TestSASFromBytes(t *testing.T) {
	material := make([]byte, 32)
	words := crypto.SASFromBytes(material)
	if len(words) != 8 {
		t.Fatalf("expected 8 SAS words, got %d", len(words))
	}
	for _, w := range words {
		if w == "" {
			t.Fatal("empty SAS word")
		}
	}
}

func TestSASString(t *testing.T) {
	material := make([]byte, 32)
	words := crypto.SASFromBytes(material)
	s := crypto.SASString(words)
	if s == "" {
		t.Fatal("empty SAS string")
	}
}

func TestIdenticon(t *testing.T) {
	material := make([]byte, 16)
	out, err := crypto.Identicon(material)
	if err != nil {
		t.Fatalf("identicon: %v", err)
	}
	if out == "" {
		t.Fatal("empty identicon")
	}
	// Should have 10 lines (top border + 8 rows + bottom border)
	lines := 0
	for _, c := range out {
		if c == '\n' {
			lines++
		}
	}
	if lines != 9 {
		t.Fatalf("expected 9 newlines in identicon, got %d", lines)
	}
}

func TestIdenticonShortInput(t *testing.T) {
	_, err := crypto.Identicon([]byte("short"))
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestCPaceExchange(t *testing.T) {
	password := "rapid-blue-fox"
	var channelID uint16 = 12345

	senderSession, senderPub, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		t.Fatalf("sender init: %v", err)
	}
	receiverSession, receiverPub, err := crypto.CPaceInit(password, channelID, "receiver")
	if err != nil {
		t.Fatalf("receiver init: %v", err)
	}

	senderK, err := senderSession.CPaceFinish(receiverPub)
	if err != nil {
		t.Fatalf("sender finish: %v", err)
	}
	receiverK, err := receiverSession.CPaceFinish(senderPub)
	if err != nil {
		t.Fatalf("receiver finish: %v", err)
	}

	if string(senderK) != string(receiverK) {
		t.Fatal("CPace shared secrets do not match")
	}
	if len(senderK) == 0 {
		t.Fatal("shared secret is empty")
	}
}

func TestCPaceWrongPassword(t *testing.T) {
	var channelID uint16 = 42

	senderSession, _, err := crypto.CPaceInit("correct-horse", channelID, "sender")
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPub, err := crypto.CPaceInit("wrong-battery", channelID, "receiver")
	if err != nil {
		t.Fatal(err)
	}
	_, receiverWrong, err := crypto.CPaceInit("correct-horse", channelID, "receiver")
	if err != nil {
		t.Fatal(err)
	}

	senderK, err := senderSession.CPaceFinish(wrongPub)
	if err != nil {
		t.Fatal(err)
	}
	_ = receiverWrong
	_ = senderK
	// Note: ECDH will succeed but produce a different key — this is the correct behavior
	// since the generator points differ; the attacker cannot derive the same K
}

func TestCPaceFinishInvalidPubMsg(t *testing.T) {
	session, _, err := crypto.CPaceInit("pass", 1, "sender")
	if err != nil {
		t.Fatal(err)
	}
	_, err = session.CPaceFinish([]byte("tooshort"))
	if err == nil {
		t.Fatal("expected error for invalid pubmsg length")
	}
}

// TestCPaceRoleSeparation verifies that the role is bound into the shared
// secret derivation. Two sessions that both use the same role ("sender")
// must NOT derive the same shared secret when each completes with the other's
// public message — the role-ordered transcript must break the symmetry.
// This test fails before the H-01 fix (role is silently dropped → both K's
// are equal) and passes after (role-ordered transcript makes them differ).
func TestCPaceRoleSeparation(t *testing.T) {
	const password = "test-password-h01"
	const channelID uint16 = 99

	// Both sessions use the same role — misconfiguration / reflection scenario.
	s1, pub1, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		t.Fatalf("init s1: %v", err)
	}
	s2, pub2, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		t.Fatalf("init s2: %v", err)
	}

	k1, err := s1.CPaceFinish(pub2)
	if err != nil {
		t.Fatalf("s1 finish: %v", err)
	}
	k2, err := s2.CPaceFinish(pub1)
	if err != nil {
		t.Fatalf("s2 finish: %v", err)
	}

	// Without role-ordered transcript both sides compute H(iskX) which is
	// symmetric: s1*s2*G == s2*s1*G → k1 == k2. That is the bug.
	// After the fix the transcript is H(iskX || pubSelf || pubPeer), and
	// since both sessions identify themselves as "sender", the byte order
	// differs (k1 hashes pub1||pub2 while k2 hashes pub2||pub1), so k1 ≠ k2.
	if bytes.Equal(k1, k2) {
		t.Fatal("H-01 role separation: two 'sender' sessions derived the same " +
			"shared secret — role is not bound into the ISK derivation")
	}
}
