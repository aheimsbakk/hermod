// Shared QUIC stream helpers: channel-ID AAD, hole-punch nonce,
// and length-prefixed framing.

package cli

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// channelIDAad returns the 2-byte big-endian encoding of id for use as
// Additional Authenticated Data in AES-GCM endpoint bundle encryption.
func channelIDAad(id uint16) []byte {
	aad := make([]byte, 2)
	binary.BigEndian.PutUint16(aad, id)
	return aad
}

// holePunchNonce derives a 32-byte session-unique hash for use as hole-punch
// probe and ack discriminators.
// The caller uses hash[0:7] for the probe payload and hash[8:15] for the ack
// payload, giving 64 bits of entropy per packet — practically unguessable
// by an off-path attacker.
// key should be the strongest available session key material (currently:
// the hybridBlobKey derived from CPace + X25519 ECDH + ML-KEM-768).
func holePunchNonce(key []byte) [32]byte {
	return sha256.Sum256(append(key, []byte("hermod-holepunch-v1")...))
}

// appendLenPrefix prepends a 4-byte big-endian length to data.
func appendLenPrefix(data []byte) []byte {
	out := make([]byte, 4+len(data))
	out[0] = byte(len(data) >> 24)
	out[1] = byte(len(data) >> 16)
	out[2] = byte(len(data) >> 8)
	out[3] = byte(len(data))
	copy(out[4:], data)
	return out
}

// readLenPrefixed reads a 4-byte big-endian length-prefixed message from r
// with a maximum allowed size of 1 MiB.
func readLenPrefixed(r io.Reader) ([]byte, error) {
	return readLenPrefixedMax(r, 1<<20)
}

// readLenPrefixedMax is like readLenPrefixed but with an explicit max byte limit.
func readLenPrefixedMax(r io.Reader, max uint32) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > max {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, max)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return buf, nil
}
