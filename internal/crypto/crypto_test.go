package crypto_test

import (
	"bytes"
	"reflect"
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
	if len(words) != 6 {
		t.Fatalf("expected 6 SAS words, got %d", len(words))
	}
	wordlist := crypto.EFFShortWordlist()
	wordSet := make(map[string]struct{}, len(wordlist))
	for _, w := range wordlist {
		wordSet[w] = struct{}{}
	}
	for _, w := range words {
		if w == "" {
			t.Fatal("empty SAS word")
		}
		if _, ok := wordSet[w]; !ok {
			t.Fatalf("SAS word %q is not in EFF Short Wordlist 1", w)
		}
	}
}

func TestSASDeterministic(t *testing.T) {
	material := []byte("12345678901234567890123456789012")
	w1 := crypto.SASFromBytes(material)
	w2 := crypto.SASFromBytes(material)
	if !reflect.DeepEqual(w1, w2) {
		t.Fatal("SASFromBytes is not deterministic")
	}
}

func TestSASDifferentInput(t *testing.T) {
	material1 := make([]byte, 32)
	material2 := make([]byte, 32)
	material2[0] = 0x01
	w1 := crypto.SASFromBytes(material1)
	w2 := crypto.SASFromBytes(material2)
	if reflect.DeepEqual(w1, w2) {
		t.Fatal("SASFromBytes produced same output for different inputs")
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

	// Sender uses the correct password.
	correctSender, correctSenderPub, err := crypto.CPaceInit("correct-horse", channelID, "sender")
	if err != nil {
		t.Fatal(err)
	}

	// Receiver with a wrong password — produces a different generator point.
	_, wrongPub, err := crypto.CPaceInit("wrong-battery", channelID, "receiver")
	if err != nil {
		t.Fatal(err)
	}

	// Receiver with the correct password — normal path.
	correctReceiver, _, err := crypto.CPaceInit("correct-horse", channelID, "receiver")
	if err != nil {
		t.Fatal(err)
	}

	// Correct-horse sender finishes with wrong-battery receiver's pub → wrong key.
	wrongK, err := correctSender.CPaceFinish(wrongPub)
	if err != nil {
		t.Fatalf("CPaceFinish with wrong password should still succeed: %v", err)
	}

	// Correct-horse receiver finishes with correct-horse sender's pub → correct key.
	referenceK, err := correctReceiver.CPaceFinish(correctSenderPub)
	if err != nil {
		t.Fatalf("CPaceFinish with correct password: %v", err)
	}

	if len(wrongK) == 0 {
		t.Fatal("wrong-password key should not be empty")
	}
	if len(referenceK) == 0 {
		t.Fatal("reference key should not be empty")
	}
	if string(wrongK) == string(referenceK) {
		t.Fatal("wrong password must produce a different key than the correct password")
	}
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

// --- Hybrid KEM tests ---

// TestGenerateX25519KeyPair verifies X25519 key generation works.
func TestGenerateX25519KeyPair(t *testing.T) {
	priv, pubBytes, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	if priv == nil {
		t.Fatal("expected non-nil private key")
	}
	if len(pubBytes) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(pubBytes))
	}
	// Verify public key can be parsed back
	pub, err := crypto.NewX25519PubFromBytes(pubBytes)
	if err != nil {
		t.Fatalf("NewX25519PubFromBytes: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

// TestX25519ECDH verifies two parties derive the same shared secret.
func TestX25519ECDH(t *testing.T) {
	alicePriv, alicePub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, bobPub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	aliceKey, err := crypto.NewX25519PubFromBytes(bobPub)
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := crypto.NewX25519PubFromBytes(alicePub)
	if err != nil {
		t.Fatal(err)
	}

	aliceSS, err := crypto.ECDHX25519(alicePriv, aliceKey)
	if err != nil {
		t.Fatalf("alice ECDH: %v", err)
	}
	bobSS, err := crypto.ECDHX25519(bobPriv, bobKey)
	if err != nil {
		t.Fatalf("bob ECDH: %v", err)
	}

	if len(aliceSS) != 32 {
		t.Fatalf("expected 32-byte shared secret, got %d", len(aliceSS))
	}
	if string(aliceSS) != string(bobSS) {
		t.Fatal("X25519 ECDH shared secrets do not match")
	}
}

// TestGenerateMLKEMReceiverKey verifies ML-KEM key generation.
func TestGenerateMLKEMReceiverKey(t *testing.T) {
	kp, err := crypto.GenerateMLKEMReceiverKey()
	if err != nil {
		t.Fatalf("GenerateMLKEMReceiverKey: %v", err)
	}
	if kp.DecapKey == nil {
		t.Fatal("expected non-nil decapsulation key")
	}
	if kp.EncapKey == nil {
		t.Fatal("expected non-nil encapsulation key")
	}
	ekBytes := kp.EncapKeyBytes()
	if len(ekBytes) != 1184 {
		t.Fatalf("expected 1184-byte enc key, got %d", len(ekBytes))
	}
}

// TestMLKEMRoundTrip verifies encapsulate/decapsulate produces the same key.
func TestMLKEMRoundTrip(t *testing.T) {
	kp, err := crypto.GenerateMLKEMReceiverKey()
	if err != nil {
		t.Fatal(err)
	}
	ekBytes := kp.EncapKeyBytes()

	ek, err := crypto.NewEncapsulationKey768Bytes(ekBytes)
	if err != nil {
		t.Fatalf("NewEncapsulationKey768Bytes: %v", err)
	}

	ss1, ct := crypto.EncapsulateMLKEM(ek)
	if len(ss1) != 32 {
		t.Fatalf("expected 32-byte shared key, got %d", len(ss1))
	}
	if len(ct) != 1088 {
		t.Fatalf("expected 1088-byte ciphertext, got %d", len(ct))
	}

	ss2, err := crypto.DecapsulateMLKEM(kp.DecapKey, ct)
	if err != nil {
		t.Fatalf("DecapsulateMLKEM: %v", err)
	}
	if string(ss1) != string(ss2) {
		t.Fatal("ML-KEM shared secrets do not match")
	}
}

// TestMLKEMInvalidCiphertext verifies decapsulation rejects bad ciphertexts.
func TestMLKEMInvalidCiphertext(t *testing.T) {
	kp, err := crypto.GenerateMLKEMReceiverKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = crypto.DecapsulateMLKEM(kp.DecapKey, []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid ciphertext length")
	}
}

// TestDeriveHybridBlobKey verifies determinism and basic properties.
func TestDeriveHybridBlobKey(t *testing.T) {
	kClassical := make([]byte, 32)
	ssX25519 := make([]byte, 32)
	ssMLKEM := make([]byte, 32)

	key1 := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}

	// Deterministic
	key2 := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)
	if string(key1) != string(key2) {
		t.Fatal("DeriveHybridBlobKey is not deterministic")
	}

	// Different inputs produce different keys
	ssMLKEM[0] = 0x01
	key3 := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)
	if string(key1) == string(key3) {
		t.Fatal("different inputs produced the same key")
	}
}

// TestHybridKEMEndToEnd simulates a full sender-receiver hybrid KEM exchange.
func TestHybridKEMEndToEnd(t *testing.T) {
	// Both sides have kClassical from CPace (simulated)
	kClassical := []byte("this-is-the-cpace-classical-shared-secret-thirtytwo!"[:32])

	// Sender: generate X25519 key pair
	senderPriv, senderPub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Receiver: generate X25519 + ML-KEM key pairs
	recvPriv, recvPub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	mlkemKP, err := crypto.GenerateMLKEMReceiverKey()
	if err != nil {
		t.Fatal(err)
	}

	// Exchange public keys over the (simulated) relay

	// --- Sender side ---
	// Parse receiver's X25519 pub
	recvX25519Key, err := crypto.NewX25519PubFromBytes(recvPub)
	if err != nil {
		t.Fatal(err)
	}
	// ECDH
	ssX25519Sender, err := crypto.ECDHX25519(senderPriv, recvX25519Key)
	if err != nil {
		t.Fatal(err)
	}
	// ML-KEM encapsulate
	peerEK, err := crypto.NewEncapsulationKey768Bytes(mlkemKP.EncapKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	ssMLKEMSender, kemCt := crypto.EncapsulateMLKEM(peerEK)
	hybridKeySender := crypto.DeriveHybridBlobKey(kClassical, ssX25519Sender, ssMLKEMSender)

	// --- Receiver side ---
	// Parse sender's X25519 pub
	senderX25519Key, err := crypto.NewX25519PubFromBytes(senderPub)
	if err != nil {
		t.Fatal(err)
	}
	// ECDH
	ssX25519Receiver, err := crypto.ECDHX25519(recvPriv, senderX25519Key)
	if err != nil {
		t.Fatal(err)
	}
	// ML-KEM decapsulate
	ssMLKEMReceiver, err := crypto.DecapsulateMLKEM(mlkemKP.DecapKey, kemCt)
	if err != nil {
		t.Fatal(err)
	}
	hybridKeyReceiver := crypto.DeriveHybridBlobKey(kClassical, ssX25519Receiver, ssMLKEMReceiver)

	// Both sides must derive the same hybrid key
	if string(hybridKeySender) != string(hybridKeyReceiver) {
		t.Fatal("hybrid keys do not match between sender and receiver")
	}

	// Verify the key works for AES-GCM end-to-end
	plaintext := []byte("endpoint-bundle-data")
	aad := []byte{0x00, 0x01} // channel ID

	ct, err := crypto.SealAAD(hybridKeySender, aad, plaintext)
	if err != nil {
		t.Fatalf("sender seal: %v", err)
	}
	decrypted, err := crypto.OpenAAD(hybridKeyReceiver, aad, ct)
	if err != nil {
		t.Fatalf("receiver open: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatal("decrypted plaintext mismatch")
	}
}

// TestHybridKEMWrongKey verifies decryption fails with wrong ML-KEM key.
func TestHybridKEMWrongKey(t *testing.T) {
	kClassical := []byte("this-is-the-cpace-classical-shared-secret-thirtytwo!"[:32])

	senderPriv, _, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, recvPub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	realKP, err := crypto.GenerateMLKEMReceiverKey()
	if err != nil {
		t.Fatal(err)
	}
	// Wrong key pair (eavesdropper)
	wrongKP, err := crypto.GenerateMLKEMReceiverKey()
	if err != nil {
		t.Fatal(err)
	}

	// Sender (correctly uses receiver's real MLKEM key)
	recvX25519Key, err := crypto.NewX25519PubFromBytes(recvPub)
	if err != nil {
		t.Fatal(err)
	}
	ssX25519, err := crypto.ECDHX25519(senderPriv, recvX25519Key)
	if err != nil {
		t.Fatal(err)
	}
	peerEK, err := crypto.NewEncapsulationKey768Bytes(realKP.EncapKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	ssMLKEM, kemCt := crypto.EncapsulateMLKEM(peerEK)
	hybridKey := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)

	// Wrong receiver: decapsulation with wrong key may succeed but
	// produces a different shared secret. AES-GCM catches the mismatch.
	wrongSS, err := crypto.DecapsulateMLKEM(wrongKP.DecapKey, kemCt)
	if err != nil {
		// Some ML-KEM implementations reject wrong key — that's also fine.
		return
	}

	// Derive wrong hybrid key and verify AES-GCM decryption fails
	wrongHybridKey := crypto.DeriveHybridBlobKey(kClassical, ssX25519, wrongSS)
	ct, err := crypto.SealAAD(hybridKey, nil, []byte("test data"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	_, err = crypto.OpenAAD(wrongHybridKey, nil, ct)
	if err == nil {
		t.Fatal("expected OpenAAD error with wrong hybrid key")
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
