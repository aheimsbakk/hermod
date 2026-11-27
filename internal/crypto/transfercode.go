// Human-readable transfer code generation and parsing.

package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// randomWordIndex returns a uniformly random index in [0, len(effShortWordlist))
// using rejection sampling on uint16 values to eliminate modulo bias.
func randomWordIndex() (int, error) {
	n := len(effShortWordlist) // 1296
	// Largest multiple of n that fits in a uint16 range (0..65535):
	// floor(65536 / n) * n = 50 * 1296 = 64800.
	limit := (65536 / n) * n
	var buf [2]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("rng word index: %w", err)
		}
		v := int(binary.BigEndian.Uint16(buf[:]))
		if v < limit {
			return v % n, nil
		}
	}
}

// GenerateTransferCode generates a random transfer code: "<uint16>-word-word-..."
// numWords is the number of words (minimum 3).
// Words are drawn from the full 1,296-entry EFF short wordlist using
// rejection sampling, giving log₂(1296^numWords) bits of passphrase entropy.
func GenerateTransferCode(numWords int) (uint16, string, error) {
	if numWords < 3 {
		numWords = 3
	}
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return 0, "", fmt.Errorf("rng: %w", err)
	}
	channelID := binary.BigEndian.Uint16(idBuf[:])

	words := make([]string, numWords)
	for i := range words {
		idx, err := randomWordIndex()
		if err != nil {
			return 0, "", err
		}
		words[i] = effShortWordlist[idx]
	}

	code := fmt.Sprintf("%d-%s", channelID, strings.Join(words, "-"))
	return channelID, code, nil
}

// ParseTransferCode parses a transfer code string into channelID and wordList.
func ParseTransferCode(code string) (uint16, []string, error) {
	parts := strings.SplitN(code, "-", 2)
	if len(parts) != 2 {
		return 0, nil, errors.New("invalid transfer code format")
	}
	var id uint16
	_, err := fmt.Sscanf(parts[0], "%d", &id)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid channel ID in transfer code: %w", err)
	}
	words := strings.Split(parts[1], "-")
	if len(words) < 3 {
		return 0, nil, errors.New("transfer code must contain at least 3 words")
	}
	return id, words, nil
}
