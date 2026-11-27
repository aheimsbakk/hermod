// SAS generation and identicon rendering for out-of-band verification.

package crypto

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// --- SAS (Short Authentication String) ---

// sasWordCount is the number of EFF Short Wordlist 1 words in the SAS.
const sasWordCount = 6

// SASFromBytes generates a human-readable SAS from 32 bytes of key material.
// Returns 6 words from the EFF Short Wordlist 1 (1296 entries), drawn using
// rejection sampling on uint16 values read from the key material.
// The output is deterministic for the same key material and has no modulo bias.
func SASFromBytes(keyMaterial []byte) []string {
	n := len(effShortWordlist) // 1296
	// Largest multiple of n that fits in a uint16 range (0..65535):
	// floor(65536 / n) * n = 50 * 1296 = 64800.
	limit := (65536 / n) * n

	words := make([]string, sasWordCount)
	wordIdx := 0
	offset := 0

	for wordIdx < sasWordCount {
		if offset+1 >= len(keyMaterial) {
			// SASFromBytes requires at least 12 bytes of key material
			// (6 words × 2 bytes each). All callers provide at least 32
			// bytes, so this path is unreachable (defense-in-depth).
			panic("SASFromBytes: insufficient key material (need ≥12 bytes)")
		}
		v := int(binary.BigEndian.Uint16(keyMaterial[offset:]))
		offset += 2
		if v < limit {
			words[wordIdx] = effShortWordlist[v%n]
			wordIdx++
		}
	}
	return words
}

// --- Identicon (Visual Fingerprint) ---

const (
	charEmpty = ' ' // U+0020: 00
	charUpper = '▀' // U+2580: 01
	charLower = '▄' // U+2584: 10
	charFull  = '█' // U+2588: 11
)

const (
	boxTopLeft     = '╔'
	boxTopRight    = '╗'
	boxBottomLeft  = '╚'
	boxBottomRight = '╝'
	boxHoriz       = '═'
	boxVert        = '║'
)

// Identicon generates a visual fingerprint from 16 bytes of key material.
// Grid: 8 rows × 16 columns (left 8 cols = entropy, right 8 = mirror).
// Returns an error if keyMaterial is shorter than 16 bytes.
func Identicon(keyMaterial []byte) (string, error) {
	if len(keyMaterial) < 16 {
		return "", fmt.Errorf("identicon: need at least 16 bytes of key material, got %d", len(keyMaterial))
	}
	grid := [8][8]rune{}
	byteIdx := 0
	bitPair := 0
	for row := 0; row < 8; row++ {
		for col := 0; col < 8; col++ {
			if bitPair >= 4 {
				byteIdx++
				bitPair = 0
			}
			b := keyMaterial[byteIdx]
			shift := uint(6 - bitPair*2)
			val := (b >> shift) & 0x03
			bitPair++
			switch val {
			case 0:
				grid[row][col] = charEmpty
			case 1:
				grid[row][col] = charUpper
			case 2:
				grid[row][col] = charLower
			case 3:
				grid[row][col] = charFull
			}
		}
	}

	var sb strings.Builder
	sb.WriteRune(boxTopLeft)
	for i := 0; i < 18; i++ {
		sb.WriteRune(boxHoriz)
	}
	sb.WriteRune(boxTopRight)
	sb.WriteByte('\n')

	for row := 0; row < 8; row++ {
		sb.WriteRune(boxVert)
		sb.WriteByte(' ')
		for col := 0; col < 8; col++ {
			sb.WriteRune(grid[row][col])
		}
		for col := 7; col >= 0; col-- {
			sb.WriteRune(grid[row][col])
		}
		sb.WriteByte(' ')
		sb.WriteRune(boxVert)
		sb.WriteByte('\n')
	}

	sb.WriteRune(boxBottomLeft)
	for i := 0; i < 18; i++ {
		sb.WriteRune(boxHoriz)
	}
	sb.WriteRune(boxBottomRight)
	return sb.String(), nil
}
