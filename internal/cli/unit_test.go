// Package cli: unit tests for helper functions that require no running server.
package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/server"
	"github.com/hermod/hermod/pkg/transfer"
)

// --- appendLenPrefix ---

// TestAppendLenPrefix verifies the 4-byte big-endian framing.
func TestAppendLenPrefix(t *testing.T) {
	data := []byte("hello")
	out := appendLenPrefix(data)
	if len(out) != 9 {
		t.Fatalf("expected 9 bytes, got %d", len(out))
	}
	// Last byte of the length field must equal 5 (len("hello")).
	if out[3] != 5 {
		t.Fatalf("expected length byte 5, got %d", out[3])
	}
	if string(out[4:]) != "hello" {
		t.Fatal("data portion mismatch")
	}
}

// TestAppendLenPrefix_Empty verifies nil input produces four zero bytes.
func TestAppendLenPrefix_Empty(t *testing.T) {
	out := appendLenPrefix(nil)
	if len(out) != 4 {
		t.Fatalf("expected 4 bytes for empty input, got %d", len(out))
	}
	for _, b := range out {
		if b != 0 {
			t.Fatal("expected all zero bytes for empty input")
		}
	}
}

// --- readLenPrefixed ---

// TestReadLenPrefixed_Success round-trips through appendLenPrefix.
func TestReadLenPrefixed_Success(t *testing.T) {
	data := []byte("hello world")
	framed := appendLenPrefix(data)
	got, err := readLenPrefixed(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("expected %q, got %q", data, got)
	}
}

// TestReadLenPrefixed_TruncatedHeader fails when the 4-byte header is incomplete.
func TestReadLenPrefixed_TruncatedHeader(t *testing.T) {
	_, err := readLenPrefixed(bytes.NewReader([]byte{0x00, 0x00}))
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

// TestReadLenPrefixed_TruncatedBody fails when the body is shorter than declared.
func TestReadLenPrefixed_TruncatedBody(t *testing.T) {
	r := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x05, 'h', 'i'}) // declares 5, has 2
	_, err := readLenPrefixed(r)
	if err == nil {
		t.Fatal("expected error for truncated body")
	}
}

// TestReadLenPrefixed_TooLarge rejects messages exceeding the 1 MiB limit.
func TestReadLenPrefixed_TooLarge(t *testing.T) {
	// Big-endian encoding of 1<<20 + 1 = 1_048_577
	r := bytes.NewReader([]byte{0x00, 0x10, 0x00, 0x01})
	_, err := readLenPrefixed(r)
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
}

// --- buildPayload ---

// TestBuildPayload_TextKind verifies KindText uses the input string directly.
func TestBuildPayload_TextKind(t *testing.T) {
	input := "hello world"
	meta, reader, size, err := buildPayload(input, transfer.KindText, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Kind != transfer.KindText {
		t.Fatalf("expected KindText, got %s", meta.Kind)
	}
	if meta.Size != int64(len(input)) {
		t.Fatalf("size mismatch: got %d, want %d", meta.Size, len(input))
	}
	if size != int64(len(input)) {
		t.Fatalf("returned size mismatch: got %d, want %d", size, len(input))
	}
	got, _ := io.ReadAll(reader)
	if string(got) != input {
		t.Fatal("reader content mismatch")
	}
}

// TestBuildPayload_FileKind verifies KindFile hashes and opens the file.
func TestBuildPayload_FileKind(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "payload-*.txt")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	content := []byte("file content")
	_, _ = f.Write(content)
	f.Close()

	meta, reader, size, err := buildPayload(f.Name(), transfer.KindFile, filepath.Base(f.Name()), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() {
		if c, ok := reader.(io.Closer); ok {
			c.Close()
		}
	}()
	if meta.Kind != transfer.KindFile {
		t.Fatalf("expected KindFile, got %s", meta.Kind)
	}
	if meta.Size != int64(len(content)) {
		t.Fatalf("size mismatch: got %d, want %d", meta.Size, len(content))
	}
	if size != int64(len(content)) {
		t.Fatalf("returned size mismatch: got %d, want %d", size, len(content))
	}
	got, _ := io.ReadAll(reader)
	if string(got) != string(content) {
		t.Fatal("file content mismatch")
	}
}

// TestBuildPayload_FileKind_NotExist returns an error for a missing file.
func TestBuildPayload_FileKind_NotExist(t *testing.T) {
	_, _, _, err := buildPayload("/nonexistent/path/file.txt", transfer.KindFile, "file.txt", false)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// TestBuildPayload_StreamKind reads from stdin (redirected to a pipe).
func TestBuildPayload_StreamKind(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdin := os.Stdin
	os.Stdin = pr
	defer func() { os.Stdin = oldStdin }()

	_, _ = pw.WriteString("stream data")
	pw.Close()

	meta, reader, _, err := buildPayload("", transfer.KindStream, "", true)
	if err != nil {
		t.Fatalf("buildPayload stream: %v", err)
	}
	if meta.Kind != transfer.KindStream {
		t.Fatalf("expected KindStream, got %s", meta.Kind)
	}
	got, _ := io.ReadAll(reader)
	if string(got) != "stream data" {
		t.Fatalf("stream content mismatch: got %q", got)
	}
}

// TestBuildPayload_UnknownKind returns an error for unknown kinds.
func TestBuildPayload_UnknownKind(t *testing.T) {
	_, _, _, err := buildPayload("whatever", transfer.Kind("unknown"), "", false)
	if err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

// --- saveToFile ---

// TestSaveToFile_Success writes content to a directory destination.
func TestSaveToFile_Success(t *testing.T) {
	data := []byte("hello from save")
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "out.txt",
		Size:   int64(len(data)),
		SHA256: transfer.HashBytes(data),
	}
	destDir := t.TempDir()

	if _, err := saveToFile(context.Background(), bytes.NewReader(data), meta, destDir); err != nil {
		t.Fatalf("saveToFile: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "out.txt"))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != string(data) {
		t.Fatal("output content mismatch")
	}
}

// TestSaveToFile_FilePath writes content when destination is a file path (not a dir).
func TestSaveToFile_FilePath(t *testing.T) {
	data := []byte("direct path")
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "out.txt",
		Size:   int64(len(data)),
		SHA256: transfer.HashBytes(data),
	}
	destPath := filepath.Join(t.TempDir(), "result.txt")

	if _, err := saveToFile(context.Background(), bytes.NewReader(data), meta, destPath); err != nil {
		t.Fatalf("saveToFile with file path: %v", err)
	}
	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != string(data) {
		t.Fatal("content mismatch for file path destination")
	}
}

// TestSaveToFile_EmptyName uses "received" when meta.Name is empty.
func TestSaveToFile_EmptyName(t *testing.T) {
	data := []byte("no name")
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "",
		Size:   int64(len(data)),
		SHA256: transfer.HashBytes(data),
	}
	destDir := t.TempDir()

	if _, err := saveToFile(context.Background(), bytes.NewReader(data), meta, destDir); err != nil {
		t.Fatalf("saveToFile: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(destDir, "received")); err != nil {
		t.Fatalf("expected file named 'received': %v", err)
	}
}

// TestSaveToFile_HashMismatch removes the temp file when the hash is wrong.
func TestSaveToFile_HashMismatch(t *testing.T) {
	data := []byte("hello")
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "out.txt",
		Size:   int64(len(data)),
		SHA256: strings.Repeat("0", 64),
	}
	destDir := t.TempDir()

	_, err := saveToFile(context.Background(), bytes.NewReader(data), meta, destDir)
	if err == nil {
		t.Fatal("expected error on hash mismatch")
	}
	// Temp file must not remain.
	entries, _ := os.ReadDir(destDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".hermod_tmp") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

// TestSaveToFile_ContextCancelled_CleansUp removes the temp file when ctx is
// already cancelled and the hash therefore does not match.
func TestSaveToFile_ContextCancelled_CleansUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so ctx.Err() is non-nil

	data := []byte("some data")
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "out.txt",
		SHA256: strings.Repeat("0", 64), // deliberately wrong hash
	}
	destDir := t.TempDir()

	_, err := saveToFile(ctx, bytes.NewReader(data), meta, destDir)
	if err == nil {
		t.Fatal("expected error for cancelled context with hash mismatch")
	}
	entries, _ := os.ReadDir(destDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".hermod_tmp") {
			t.Errorf("temp file not cleaned up on cancellation: %s", e.Name())
		}
	}
}

// --- receivePayload ---

// TestReceivePayload_ToDestination saves to disk when destination is set.
func TestReceivePayload_ToDestination(t *testing.T) {
	data := []byte("payload to save")
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "recv.txt",
		Size:   int64(len(data)),
		SHA256: transfer.HashBytes(data),
	}
	destDir := t.TempDir()

	if _, err := receivePayload(context.Background(), meta, bytes.NewReader(data), destDir, false); err != nil {
		t.Fatalf("receivePayload: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "recv.txt"))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != string(data) {
		t.Fatal("content mismatch")
	}
}

// TestReceivePayload_PipedStdout copies to stdout when destination is empty and
// stdout is not a TTY (the standard case in tests and piped usage).
func TestReceivePayload_PipedStdout(t *testing.T) {
	data := []byte("piped output")
	meta := &transfer.Metadata{
		Kind: transfer.KindText,
		Size: int64(len(data)),
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	_, recvErr := receivePayload(context.Background(), meta, bytes.NewReader(data), "", false)

	w.Close()
	os.Stdout = oldStdout

	if recvErr != nil {
		t.Fatalf("receivePayload: %v", recvErr)
	}
	got, _ := io.ReadAll(r)
	if string(got) != string(data) {
		t.Fatalf("stdout content mismatch: got %q, want %q", got, data)
	}
}

// TestReceivePayload_TTYText covers the TTY+KindText branch of receivePayload.
// Passing stdoutIsTTY=true with a non-empty Size exercises the progressbar path.
func TestReceivePayload_TTYText(t *testing.T) {
	data := []byte("hello tty text")
	meta := &transfer.Metadata{
		Kind: transfer.KindText,
		Size: int64(len(data)),
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	_, recvErr := receivePayload(context.Background(), meta, bytes.NewReader(data), "", true)

	w.Close()
	os.Stdout = oldStdout

	if recvErr != nil {
		t.Fatalf("receivePayload TTY text: %v", recvErr)
	}
	got, _ := io.ReadAll(r)
	// receivePayload appends a newline to text output so the shell prompt
	// starts on a new line. The test expectation includes that trailing newline.
	want := append(data, '\n')
	if string(got) != string(want) {
		t.Fatalf("stdout content mismatch: got %q, want %q", got, want)
	}
}

// TestReceivePayload_TTYTextNoSize covers the TTY+KindText branch with Size==0.
func TestReceivePayload_TTYTextNoSize(t *testing.T) {
	data := []byte("no size text")
	meta := &transfer.Metadata{
		Kind: transfer.KindText,
		Size: 0,
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	_, recvErr := receivePayload(context.Background(), meta, bytes.NewReader(data), "", true)

	w.Close()
	os.Stdout = oldStdout

	if recvErr != nil {
		t.Fatalf("receivePayload TTY text no-size: %v", recvErr)
	}
	got, _ := io.ReadAll(r)
	// receivePayload appends a newline to text output so the shell prompt
	// starts on a new line. The test expectation includes that trailing newline.
	want := append(data, '\n')
	if string(got) != string(want) {
		t.Fatalf("stdout content mismatch: got %q, want %q", got, want)
	}
}

// TestReceivePayload_TTYFile covers the TTY+KindFile branch (saves to CWD).
func TestReceivePayload_TTYFile(t *testing.T) {
	data := []byte("file via tty")
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "tty_output.txt",
		Size:   int64(len(data)),
		SHA256: transfer.HashBytes(data),
	}

	// Run in a temp directory so the file written to "." lands there.
	origDir, _ := os.Getwd()
	destDir := t.TempDir()
	if err := os.Chdir(destDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(origDir) //nolint:errcheck

	if _, err := receivePayload(context.Background(), meta, bytes.NewReader(data), "", true); err != nil {
		t.Fatalf("receivePayload TTY file: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(destDir, "tty_output.txt"))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != string(data) {
		t.Fatal("TTY file content mismatch")
	}
}

// TestToSlogLevel verifies every VerboseLevel maps to the expected slog.Level.
func TestToSlogLevel(t *testing.T) {
	cases := []struct {
		in   VerboseLevel
		want slog.Level
	}{
		{VerboseNone, slog.LevelError},
		{VerboseError, slog.LevelError},
		{VerboseWarning, slog.LevelWarn},
		{VerboseInfo, slog.LevelInfo},
		{VerboseDebug, slog.LevelDebug},
	}
	for _, tc := range cases {
		got := toSlogLevel(tc.in)
		if got != tc.want {
			t.Errorf("toSlogLevel(%v): got %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestParseVerboseLevel_AllValid verifies every valid label (including upper-case).
func TestParseVerboseLevel_AllValid(t *testing.T) {
	cases := map[string]VerboseLevel{
		"none":    VerboseNone,
		"NONE":    VerboseNone,
		"error":   VerboseError,
		"ERROR":   VerboseError,
		"warning": VerboseWarning,
		"WARNING": VerboseWarning,
		"info":    VerboseInfo,
		"INFO":    VerboseInfo,
		"debug":   VerboseDebug,
		"DEBUG":   VerboseDebug,
	}
	for s, want := range cases {
		got, ok := parseVerboseLevel(s)
		if !ok {
			t.Errorf("parseVerboseLevel(%q): ok=false", s)
		}
		if got != want {
			t.Errorf("parseVerboseLevel(%q): got %v, want %v", s, got, want)
		}
	}
}

// TestParseVerboseLevel_Invalid rejects unrecognised strings.
func TestParseVerboseLevel_Invalid(t *testing.T) {
	_, ok := parseVerboseLevel("verbose")
	if ok {
		t.Fatal("expected ok=false for 'verbose'")
	}
}

// TestLogWarnAndError verifies logWarn and logError do not panic.
func TestLogWarnAndError(t *testing.T) {
	applyVerbosity(VerboseWarning)
	logWarn("test warning message")
	logError("test error message")
	applyVerbosity(VerboseNone) // restore
}

// --- envOrDefault / configServerURL ---

// TestEnvOrDefault_Set returns the env value when it is non-empty.
func TestEnvOrDefault_Set(t *testing.T) {
	t.Setenv("TEST_HERMOD_ENV_12345", "custom-value")
	got := envOrDefault("TEST_HERMOD_ENV_12345", "default")
	if got != "custom-value" {
		t.Fatalf("expected 'custom-value', got %q", got)
	}
}

// TestEnvOrDefault_NotSet returns the default when the env var is empty.
func TestEnvOrDefault_NotSet(t *testing.T) {
	t.Setenv("TEST_HERMOD_ENV_UNSET_99999", "")
	got := envOrDefault("TEST_HERMOD_ENV_UNSET_99999", "my-default")
	if got != "my-default" {
		t.Fatalf("expected 'my-default', got %q", got)
	}
}

// TestConfigServerURL_FromEnv reads HERMOD_SERVER when set.
func TestConfigServerURL_FromEnv(t *testing.T) {
	t.Setenv("HERMOD_SERVER", "wss://env-server.example.com:4376")
	got := configServerURL()
	if got != "wss://env-server.example.com:4376" {
		t.Fatalf("expected env server URL, got %q", got)
	}
}

// TestConfigServerURL_Fallback returns the hardcoded default when env is empty
// and no config exists.
func TestConfigServerURL_Fallback(t *testing.T) {
	t.Setenv("HERMOD_SERVER", "")
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	got := configServerURL()
	if got != "wss://localhost:4376" {
		t.Fatalf("expected fallback URL, got %q", got)
	}
}

// --- runTrust ---

// TestRunTrust_URLNormalization verifies runTrust prepends wss:// when no scheme
// is given, then fails trying to connect (no server running).
func TestRunTrust_URLNormalization(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)

	err := runTrust("localhost:19999", "")
	if err == nil {
		t.Fatal("expected error (no server at localhost:19999)")
	}
	if !strings.Contains(err.Error(), "fetch fingerprint") {
		t.Errorf("expected 'fetch fingerprint' in error, got: %v", err)
	}
}

// --- runServe ---

// TestRunServe_InvalidAddress verifies runServe returns an error immediately
// when given an address that cannot be bound, while still exercising the
// config-load and cert-generation paths.
func TestRunServe_InvalidAddress(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)

	err := runServe("not-an-address:xyz", 60*time.Second, 5, 15, server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures)
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

// --- applyVerbosity ---

// TestApplyVerbosity_Debug covers the stdlog.SetOutput(os.Stderr) branch.
func TestApplyVerbosity_Debug(t *testing.T) {
	applyVerbosity(VerboseDebug)
	applyVerbosity(VerboseNone) // restore to default
}

// --- cancelledByPeer ---

// TestCancelledByPeer_Default covers the fallback "cancelled by peer" message
// for a message that is neither "cancelled:sender" nor "cancelled:receiver".
func TestCancelledByPeer_Default(t *testing.T) {
	appErr := &quic.ApplicationError{
		ErrorCode:    cancelCodeUser,
		ErrorMessage: "cancelled:custom",
	}
	result := cancelledByPeer(appErr)
	if result == nil {
		t.Fatal("expected non-nil error for custom cancel message")
	}
	if !strings.Contains(result.Error(), "cancelled by peer") {
		t.Errorf("expected 'cancelled by peer' in message, got: %v", result)
	}
}

// --- root command ---

// TestExecuteArgs_InvalidVerbose covers the PersistentPreRunE error path when
// --verbose receives an unrecognised value.
func TestExecuteArgs_InvalidVerbose(t *testing.T) {
	err := ExecuteArgs([]string{"hermod", "--verbose", "notavalidlevel", "rx", "dummy-code-xyz"})
	if err == nil {
		t.Fatal("expected error for invalid --verbose value")
	}
	if !strings.Contains(err.Error(), "invalid --verbose value") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestExecute_NoArgs covers the Execute() function (uses os.Args).
// With just the binary name cobra prints help and returns nil.
func TestExecute_NoArgs(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"hermod"}
	defer func() { os.Args = oldArgs }()
	_ = Execute()
}

// --- configServerURL ---

// TestConfigServerURL_FromConfig covers the cfg.ServerURL branch when the env var
// is empty but a config file with server_url exists.
func TestConfigServerURL_FromConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HERMOD_SERVER", "")

	cfgDir := filepath.Join(dir, ".config", "hermod")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	cfgContent := "server_url: wss://config-server.example.com:4376\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got := configServerURL()
	if got != "wss://config-server.example.com:4376" {
		t.Fatalf("expected config server URL, got %q", got)
	}
}

// --- promptSASVerification ---

// TestPromptSASVerification_TTYError covers the openTTYFunc error path in
// promptSASVerification (the thin wrapper around promptSASVerificationFrom).
func TestPromptSASVerification_TTYError(t *testing.T) {
	origFn := openTTYFunc
	defer func() { openTTYFunc = origFn }()

	openTTYFunc = func() (*os.File, error) {
		return nil, fmt.Errorf("no tty in test")
	}

	_, err := promptSASVerification(tls.ConnectionState{}, nil)
	if err == nil {
		t.Fatal("expected error from promptSASVerification when openTTYFunc fails")
	}
	if !strings.Contains(err.Error(), "open tty for SAS prompt") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// --- cobra command wiring ---

// TestExecuteArgs_ServeViaCommand exercises the newServeCmd RunE closure
// by passing an invalid listen address (error is expected and fast).
func TestExecuteArgs_ServeViaCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)

	err := ExecuteArgs([]string{"hermod", "serve", "--listen", "notanaddress:x"})
	if err == nil {
		t.Fatal("expected error for invalid listen address via cobra")
	}
}

// TestExecuteArgs_TrustViaCommand exercises the newTrustCmd RunE closure by
// passing a host where no server is listening (error is expected and fast).
func TestExecuteArgs_TrustViaCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)

	err := ExecuteArgs([]string{"hermod", "trust", "localhost:19998"})
	if err == nil {
		t.Fatal("expected error (no server at localhost:19998)")
	}
	if !strings.Contains(err.Error(), "fetch fingerprint") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- receivePayload edge cases ---

// TestReceivePayload_TTYUnknownKind verifies that an unrecognised Kind in TTY mode
// falls through to the trailing return nil in the outer switch.
func TestReceivePayload_TTYUnknownKind(t *testing.T) {
	meta := &transfer.Metadata{
		Kind: transfer.Kind("unknown-kind-xyz"),
		Size: 0,
	}
	_, err := receivePayload(context.Background(), meta, strings.NewReader(""), "", true)
	if err != nil {
		t.Fatalf("unexpected error for unknown kind in TTY mode: %v", err)
	}
}

// --- requireTrustedServer ---

// TestRequireTrustedServer_Trusted returns the fingerprint when the server is pinned.
func TestRequireTrustedServer_Trusted(t *testing.T) {
	cfg := config.Default()
	want := strings.Repeat("a", 64)
	cfg.TrustedServers["wss://example.com:4376"] = want

	got, err := requireTrustedServer(cfg, "wss://example.com:4376")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("expected fingerprint %q, got %q", want, got)
	}
}

// TestRequireTrustedServer_Untrusted returns an error when the server is not pinned.
func TestRequireTrustedServer_Untrusted(t *testing.T) {
	cfg := config.Default() // trusted_servers is empty

	_, err := requireTrustedServer(cfg, "wss://unknown.example.com:4376")
	if err == nil {
		t.Fatal("expected error for unpinned server, got nil")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("expected 'not trusted' in error, got: %v", err)
	}
}

// TestRequireTrustedServer_EmptyFingerprint treats an empty fingerprint as untrusted.
func TestRequireTrustedServer_EmptyFingerprint(t *testing.T) {
	cfg := config.Default()
	cfg.TrustedServers["wss://example.com:4376"] = "" // empty = not properly pinned

	_, err := requireTrustedServer(cfg, "wss://example.com:4376")
	if err == nil {
		t.Fatal("expected error for empty fingerprint, got nil")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("expected 'not trusted' in error, got: %v", err)
	}
}

// --- server trust enforcement ---

// TestRunTx_UntrustedServerAborts verifies that tx returns a "not trusted"
// error when the target server has no pinned certificate in trusted_servers.
// This test fails before the fix because the current code connects without
// any certificate verification instead of aborting.
func TestRunTx_UntrustedServerAborts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HERMOD_SERVER", "")

	// Fresh config — no trusted_servers entry for the target server.
	err := runTx("hello text", "wss://untrusted.example.com:4376", 3, false, ":0", false)
	if err == nil {
		t.Fatal("expected error for untrusted server, got nil")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("expected 'not trusted' in error, got: %v", err)
	}
}

// TestRunRx_UntrustedServerAborts verifies that rx returns a "not trusted"
// error when the target server has no pinned certificate in trusted_servers.
func TestRunRx_UntrustedServerAborts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HERMOD_SERVER", "")

	// Fresh config — no trusted_servers entry for the target server.
	err := runRx("3-apple-banana-cherry", "", "wss://untrusted.example.com:4376", false, ":0", false)
	if err == nil {
		t.Fatal("expected error for untrusted server, got nil")
	}
	if !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("expected 'not trusted' in error, got: %v", err)
	}
}

// --- quiet mode ---

// testCapturingStderr redirects os.Stderr to a pipe for the duration of fn,
// then returns everything written to it.
func testCapturingStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = old }()

	fn()

	w.Close()
	got, _ := io.ReadAll(r)
	return string(got)
}

// TestPrintStatus_Normal verifies printStatus writes to stderr when quietMode is off.
func TestPrintStatus_Normal(t *testing.T) {
	quietMode = false
	defer func() { quietMode = false }()

	out := testCapturingStderr(t, func() {
		printStatus("hello %s", "world")
	})
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected 'hello world' in stderr, got: %q", out)
	}
}

// TestPrintStatus_Quiet verifies printStatus is silent when quietMode is on.
func TestPrintStatus_Quiet(t *testing.T) {
	quietMode = true
	defer func() { quietMode = false }()

	out := testCapturingStderr(t, func() {
		printStatus("should not appear")
	})
	if out != "" {
		t.Errorf("expected no output in quiet mode, got: %q", out)
	}
}

// TestExecuteArgs_QuietFlag verifies -q is accepted and sets quietMode.
func TestExecuteArgs_QuietFlag(t *testing.T) {
	defer func() { quietMode = false }()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HERMOD_SERVER", "")

	// runTx will fail fast (no trusted server) but PersistentPreRunE still runs.
	_ = ExecuteArgs([]string{"hermod", "-q", "tx", "hello"})
	if !quietMode {
		t.Fatal("expected quietMode=true after -q flag")
	}
}

// TestExecuteArgs_QuietLong verifies --quiet is accepted and sets quietMode.
func TestExecuteArgs_QuietLong(t *testing.T) {
	defer func() { quietMode = false }()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HERMOD_SERVER", "")

	_ = ExecuteArgs([]string{"hermod", "--quiet", "tx", "hello"})
	if !quietMode {
		t.Fatal("expected quietMode=true after --quiet flag")
	}
}

// TestExecuteArgs_QuietAndVerbose verifies -q and --verbose can be combined
// without error: quiet suppresses printStatus, verbose controls log output.
func TestExecuteArgs_QuietAndVerbose(t *testing.T) {
	defer func() { quietMode = false; applyVerbosity(VerboseNone) }()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HERMOD_SERVER", "")

	err := ExecuteArgs([]string{"hermod", "-q", "--verbose", "info", "tx", "hello"})
	// Error is expected (untrusted server) but it must not be a flag-parse error.
	if err != nil && strings.Contains(err.Error(), "invalid") {
		t.Errorf("unexpected flag error: %v", err)
	}
	if !quietMode {
		t.Fatal("expected quietMode=true when -q and --verbose are combined")
	}
	if currentLevel != VerboseInfo {
		t.Errorf("expected VerboseInfo, got %v", currentLevel)
	}
}

// TestQuietMode_SaveToFile verifies file transfer still writes the file and
// produces no extra output on stderr when quietMode is on (regression guard
// for the `isTTY && !quietMode` progress-bar gate).
func TestQuietMode_SaveToFile(t *testing.T) {
	quietMode = true
	defer func() { quietMode = false }()

	data := []byte("quiet file content")
	meta := &transfer.Metadata{
		Kind:   transfer.KindFile,
		Name:   "quiet.txt",
		Size:   int64(len(data)),
		SHA256: transfer.HashBytes(data),
	}
	destDir := t.TempDir()

	out := testCapturingStderr(t, func() {
		if _, err := saveToFile(context.Background(), bytes.NewReader(data), meta, destDir); err != nil {
			t.Errorf("saveToFile: %v", err)
		}
	})

	// File must be written correctly.
	got, err := os.ReadFile(filepath.Join(destDir, "quiet.txt"))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != string(data) {
		t.Fatal("file content mismatch in quiet mode")
	}
	// No progress bar noise on stderr.
	if out != "" {
		t.Errorf("expected no stderr output in quiet mode, got: %q", out)
	}
}

// TestQuietMode_ReceivePayload_Text verifies text payload still reaches stdout
// in quiet mode — content is never suppressed, only status output is.
func TestQuietMode_ReceivePayload_Text(t *testing.T) {
	quietMode = true
	defer func() { quietMode = false }()

	data := []byte("quiet text payload")
	meta := &transfer.Metadata{Kind: transfer.KindText, Size: int64(len(data))}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	_, recvErr := receivePayload(context.Background(), meta, bytes.NewReader(data), "", false)

	w.Close()
	os.Stdout = oldStdout

	if recvErr != nil {
		t.Fatalf("receivePayload: %v", recvErr)
	}
	got, _ := io.ReadAll(r)
	// Content must reach stdout unchanged. The piped (non-TTY) path does not
	// append a trailing newline — that is only added in the interactive TTY path.
	if string(got) != string(data) {
		t.Fatalf("stdout mismatch: got %q, want %q", got, data)
	}
}

// TestRunServe_ExistingCert verifies the else-branch of the cert-generation block
// in runServe: when a certificate already exists the function reuses it.
func TestRunServe_ExistingCert(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("APPDATA", dir)

	// First call: generates and persists the certificate.
	_ = runServe("notanaddress:x", 60*time.Second, 5, 15, server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures)

	// Second call: cert already exists → takes the else-branch.
	err := runServe("notanaddress:x", 60*time.Second, 5, 15, server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures)
	if err == nil {
		t.Fatal("expected error for invalid listen address on second runServe call")
	}
}
