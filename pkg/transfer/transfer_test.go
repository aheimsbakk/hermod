package transfer_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/hermod/hermod/pkg/transfer"
)

func TestClassifyInputFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	kind, name, err := transfer.ClassifyInput(f.Name(), false)
	if err != nil {
		t.Fatal(err)
	}
	if kind != transfer.KindFile {
		t.Fatalf("expected KindFile, got %s", kind)
	}
	if name == "" {
		t.Fatal("expected non-empty filename")
	}
}

func TestClassifyInputText(t *testing.T) {
	kind, _, err := transfer.ClassifyInput("hello world", false)
	if err != nil {
		t.Fatal(err)
	}
	if kind != transfer.KindText {
		t.Fatalf("expected KindText, got %s", kind)
	}
}

func TestClassifyInputDash(t *testing.T) {
	kind, _, err := transfer.ClassifyInput("-", false)
	if err != nil {
		t.Fatal(err)
	}
	if kind != transfer.KindStream {
		t.Fatalf("expected KindStream, got %s", kind)
	}
}

func TestClassifyInputPipedStdin(t *testing.T) {
	kind, _, err := transfer.ClassifyInput("", true)
	if err != nil {
		t.Fatal(err)
	}
	if kind != transfer.KindStream {
		t.Fatalf("expected KindStream, got %s", kind)
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := []byte("test content")
	os.WriteFile(path, content, 0o644)

	hash, size, err := transfer.HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Fatal("empty hash")
	}
	if size != int64(len(content)) {
		t.Fatalf("expected size %d, got %d", len(content), size)
	}

	// Same content should produce same hash
	hash2, _, _ := transfer.HashFile(path)
	if hash != hash2 {
		t.Fatal("hash not deterministic")
	}
}

func TestHashFileMissing(t *testing.T) {
	_, _, err := transfer.HashFile("/nonexistent/file")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHashBytes(t *testing.T) {
	data := []byte("hello")
	h := transfer.HashBytes(data)
	if len(h) != 64 {
		t.Fatalf("expected 64-char hex, got %d chars", len(h))
	}
	// Deterministic
	if transfer.HashBytes(data) != h {
		t.Fatal("not deterministic")
	}
}

func TestEncodeDecodeMetadata(t *testing.T) {
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "document.pdf",
		Size:   1024,
		SHA256: "aabbccdd",
	}
	data, err := transfer.EncodeMetadata(meta)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	decoded, err := transfer.DecodeMetadata(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Kind != meta.Kind {
		t.Fatalf("kind mismatch: %s != %s", decoded.Kind, meta.Kind)
	}
	if decoded.Name != meta.Name {
		t.Fatalf("name mismatch: %s != %s", decoded.Name, meta.Name)
	}
	if decoded.Size != meta.Size {
		t.Fatalf("size mismatch")
	}
}

func TestDecodeMetadataInvalid(t *testing.T) {
	_, err := transfer.DecodeMetadata([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestSafeDestinationPath(t *testing.T) {
	dir := t.TempDir()
	name := "file.txt"

	// First time: no collision
	p1 := transfer.SafeDestinationPath(dir, name)
	expected := filepath.Join(dir, name)
	if p1 != expected {
		t.Fatalf("expected %s, got %s", expected, p1)
	}

	// Create the file
	os.WriteFile(p1, []byte("data"), 0o644)

	// Second time: collision -> file(1).txt
	p2 := transfer.SafeDestinationPath(dir, name)
	if p2 == p1 {
		t.Fatal("expected different path on collision")
	}

	// Create the file again
	os.WriteFile(p2, []byte("data"), 0o644)

	// Third time: file(2).txt
	p3 := transfer.SafeDestinationPath(dir, name)
	if p3 == p1 || p3 == p2 {
		t.Fatal("expected unique path")
	}
}

func TestTempPath(t *testing.T) {
	p := transfer.TempPath("/some/dir/file.txt")
	if p != "/some/dir/file.txt.hermod_tmp" {
		t.Fatalf("unexpected temp path: %s", p)
	}
}

func TestVerifyStream(t *testing.T) {
	data := []byte("hello world!")
	expected := transfer.HashBytes(data)

	var dst bytes.Buffer
	err := transfer.VerifyStream(bytes.NewReader(data), &dst, expected)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if dst.String() != string(data) {
		t.Fatal("data mismatch")
	}
}

func TestVerifyStreamHashMismatch(t *testing.T) {
	data := []byte("hello")
	err := transfer.VerifyStream(bytes.NewReader(data), &bytes.Buffer{}, "wronghash")
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
}
