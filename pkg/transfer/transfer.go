// Package transfer handles payload metadata, classification, and stream integrity.
package transfer

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Kind describes the payload type.
type Kind string

const (
	KindFile   Kind = "file"
	KindText   Kind = "text"
	KindStream Kind = "stream"
)

// Metadata is transmitted in QUIC stream 0 before the payload stream.
type Metadata struct {
	Kind   Kind   `json:"kind"`
	Name   string `json:"name,omitempty"` // original filename for KindFile
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"` // hex-encoded SHA-256 of raw payload
}

// ClassifyInput determines the Kind and associated metadata for a given input argument.
// isStdinPiped indicates whether stdin is piped (not a TTY).
func ClassifyInput(arg string, isStdinPiped bool) (Kind, string, error) {
	if arg == "-" || (arg == "" && isStdinPiped) {
		return KindStream, "", nil
	}
	fi, err := os.Stat(arg)
	if err == nil && !fi.IsDir() {
		return KindFile, filepath.Base(arg), nil
	}
	return KindText, "", nil
}

// HashFile computes the SHA-256 of the file at path and returns the hex digest.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("compute hash: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), n, nil
}

// HashBytes computes the SHA-256 of a byte slice.
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

// EncodeMetadata serializes a Metadata to JSON bytes.
func EncodeMetadata(m *Metadata) ([]byte, error) {
	return json.Marshal(m)
}

// DecodeMetadata deserializes Metadata from JSON bytes.
func DecodeMetadata(data []byte) (*Metadata, error) {
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}
	return &m, nil
}

// SafeDestinationPath resolves the output file path, appending an integer
// suffix to avoid overwriting existing files. E.g., document(1).pdf.
// It strips all directory components from name to prevent path traversal.
func SafeDestinationPath(dir, name string) string {
	// Strip directory components supplied by an untrusted remote peer.
	name = filepath.Base(name)
	if name == "" || name == "." || name == ".." {
		name = "received"
	}
	candidate := filepath.Join(dir, name)
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 1; i <= 9999; i++ {
		candidate = filepath.Join(dir, base+"("+strconv.Itoa(i)+")"+ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return candidate
}

// TempPath returns the temporary download path for a given destination.
func TempPath(dest string) string {
	return dest + ".hermod_tmp"
}

// HashStream copies all bytes from r to w, computing SHA-256 in parallel.
// Returns the hex-encoded digest. This avoids buffering large streams before
// hashing (M-07).
func HashStream(r io.Reader, w io.Writer) (string, error) {
	h := sha256.New()
	tr := io.TeeReader(r, h)
	if _, err := io.Copy(w, tr); err != nil {
		return "", fmt.Errorf("stream copy: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// VerifyStream copies from r to w using a TeeReader, computing SHA-256 on-the-fly.
// Returns an error if the final hash does not match expected.
func VerifyStream(r io.Reader, w io.Writer, expected string) error {
	h := sha256.New()
	tr := io.TeeReader(r, h)
	if _, err := io.Copy(w, tr); err != nil {
		return fmt.Errorf("stream copy: %w", err)
	}
	got := fmt.Sprintf("%x", h.Sum(nil))
	if got != expected {
		return fmt.Errorf("SHA-256 mismatch: computed %s, expected %s", got, expected)
	}
	return nil
}
