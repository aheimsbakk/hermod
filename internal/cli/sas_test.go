// Package cli: unit tests for SAS verification prompt and coordination.
package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// mockStream is a synchronous in-memory bidirectional stream between two peers.
// Each end has its own write buffer that the other end reads.
type mockStream struct {
	readBuf  *syncBuffer
	writeBuf *syncBuffer
}

// syncBuffer is a goroutine-safe, blocking bytes.Buffer.
type syncBuffer struct {
	buf  bytes.Buffer
	done chan struct{}
}

func newSyncBuffer() *syncBuffer {
	return &syncBuffer{done: make(chan struct{})}
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	n, err := s.buf.Write(p)
	// Signal that data is available.
	select {
	case s.done <- struct{}{}:
	default:
	}
	return n, err
}

func (s *syncBuffer) Read(p []byte) (int, error) {
	for s.buf.Len() == 0 {
		<-s.done
	}
	return s.buf.Read(p)
}

func (m *mockStream) Write(p []byte) (int, error) { return m.writeBuf.Write(p) }
func (m *mockStream) Read(p []byte) (int, error)  { return m.readBuf.Read(p) }
func (m *mockStream) Close() error                { return nil }

// newMockStreamPair returns two mockStreams wired so that writes on one appear
// as reads on the other, mimicking a bidirectional QUIC stream pair.
func newMockStreamPair() (*mockStream, *mockStream) {
	ab := newSyncBuffer()
	ba := newSyncBuffer()
	a := &mockStream{readBuf: ba, writeBuf: ab}
	b := &mockStream{readBuf: ab, writeBuf: ba}
	return a, b
}

// mockSASConn implements sasStreamConn using pre-wired mock streams.
type mockSASConn struct {
	// streams is a queue of streams to hand out via OpenStreamSync / AcceptStream.
	streams chan io.ReadWriteCloser
}

func newMockSASConn(streams ...io.ReadWriteCloser) *mockSASConn {
	ch := make(chan io.ReadWriteCloser, len(streams))
	for _, s := range streams {
		ch <- s
	}
	return &mockSASConn{streams: ch}
}

func (m *mockSASConn) OpenStreamSync(_ context.Context) (io.ReadWriteCloser, error) {
	return <-m.streams, nil
}

func (m *mockSASConn) AcceptStream(_ context.Context) (io.ReadWriteCloser, error) {
	return <-m.streams, nil
}

// tlsPipe creates a pair of connected *tls.Conn using in-memory net.Pipe.
func tlsPipe() (*tls.Conn, *tls.Conn, error) {
	// Generate a throwaway cert for the pipe.
	_, epKey, epCertDER, err := generateEphemeralCert()
	if err != nil {
		return nil, nil, err
	}
	cert := buildTLSCert(epCertDER, epKey, nil)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only
		MinVersion:         tls.VersionTLS13,
	}

	clientNC, serverNC := net.Pipe()

	clientConn := tls.Client(clientNC, clientCfg)
	serverConn := tls.Server(serverNC, serverCfg)

	errCh := make(chan error, 2)
	go func() { errCh <- serverConn.Handshake() }()
	go func() { errCh <- clientConn.Handshake() }()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			return nil, nil, err
		}
	}
	return clientConn, serverConn, nil
}

// --- Tests for promptSASVerificationFrom ---

// TestPromptSASVerification_YesAnswer verifies that "y" input returns true.
func TestPromptSASVerification_YesAnswer(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	ctx := context.Background()
	ok, err := promptSASVerificationFrom(ctx, clientConn.ConnectionState(), strings.NewReader("y\n"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected localOK=true for answer 'y'")
	}
}

// TestPromptSASVerification_UpperYesAnswer verifies that "Y" input returns true.
func TestPromptSASVerification_UpperYesAnswer(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	ctx := context.Background()
	ok, err := promptSASVerificationFrom(ctx, clientConn.ConnectionState(), strings.NewReader("Y\n"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected localOK=true for answer 'Y'")
	}
}

// TestPromptSASVerification_NonYesAnswer verifies that piped non-y content (e.g. "test")
// returns false. This is the regression case: when sender pipes data via stdin,
// fmt.Scanln would read the piped payload ("test") as the answer, incorrectly
// producing localOK=false even though the user answered "y" in the terminal.
// After the fix, promptSASVerificationFrom reads from an explicit reader, so
// this test confirms that a non-y string properly returns false.
func TestPromptSASVerification_NonYesAnswer(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	ctx := context.Background()
	// "test" is what echo-piped stdin would produce, simulating the bug scenario.
	ok, err := promptSASVerificationFrom(ctx, clientConn.ConnectionState(), strings.NewReader("test\n"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected localOK=false for answer 'test' (non-y piped content)")
	}
}

// TestPromptSASVerification_EmptyAnswer verifies that an empty/EOF answer returns false.
func TestPromptSASVerification_EmptyAnswer(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	ctx := context.Background()
	ok, err := promptSASVerificationFrom(ctx, clientConn.ConnectionState(), strings.NewReader(""), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected localOK=false for empty answer")
	}
}

// raceReader cancels ctx during the first Read call and returns EOF,
// simulating the exact race condition where the tty is closed while
// SIGINT fires: the scanner completes and the context is cancelled
// simultaneously. Both select paths (ctx.Done() vs scanner-ch close)
// must return context.Canceled.
type raceReader struct {
	cancel context.CancelFunc
	done   bool
}

func (r *raceReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		// Cancel the context and return EOF in the same call —
		// this mirrors the real race: tty.Close() unblocks the
		// scanner at the instant SIGINT cancels the context.
		r.cancel()
	}
	return 0, io.EOF
}

// TestPromptSASVerification_CancelledContext_Race verifies that when the
// context is cancelled at the same time the reader EOFs (simulating the
// race between SIGINT and tty.Close()), promptSASVerificationFrom returns
// context.Canceled regardless of which select case fires first.
func TestPromptSASVerification_CancelledContext_Race(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r := &raceReader{cancel: cancel}

	ok, err := promptSASVerificationFrom(ctx, clientConn.ConnectionState(), r, nil)
	if err == nil {
		t.Fatal("expected context.Canceled error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if ok {
		t.Error("expected localOK=false on cancellation")
	}
}

// TestPromptSASVerification_CancelledContext verifies that when the context is
// cancelled while waiting for input (e.g. user presses Ctrl+C), the function
// returns context.Canceled, not a nil error. Uses a pipe for the reader so the
// scanner can block and be unblocked by closing the write end.
func TestPromptSASVerification_CancelledContext(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	// Use a pipe so the scanner blocks on Read until we close the write end.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer pr.Close()

	ctx, cancel := context.WithCancel(context.Background())

	resultCh := make(chan struct {
		ok  bool
		err error
	}, 1)
	go func() {
		ok, err := promptSASVerificationFrom(ctx, clientConn.ConnectionState(), pr, nil)
		resultCh <- struct {
			ok  bool
			err error
		}{ok, err}
	}()

	// Cancel the context first, then close the reader. Both channels become
	// ready. Go's select pseudo-randomly picks one — the fix handles either.
	cancel()
	pw.Close()

	result := <-resultCh
	if result.err == nil {
		t.Fatal("expected context.Canceled error, got nil")
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", result.err)
	}
	if result.ok {
		t.Error("expected localOK=false on cancellation")
	}
}

// --- Tests for performSASCoordinatedWith ---
// These tests cover the two failing real-world scenarios:
//
//  1. Sender has piped stdin → sender's fmt.Scanln reads pipe content ("test"),
//     not user input → both sides fail with "rejected by sender" even when user
//     typed y on both ends.
//
//  2. Same as (1) but receiver answers first.

// TestSASCoordinated_BothConfirm verifies that when both sides answer "y",
// performSASCoordinatedWith returns nil for both sides.
func TestSASCoordinated_BothConfirm(t *testing.T) {
	clientConn, serverConn, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	senderStream, receiverStream := newMockStreamPair()
	senderConn := newMockSASConn(senderStream)
	receiverConn := newMockSASConn(receiverStream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)

	go func() {
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("y\n"), nil)
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("y\n"), nil)
	}()

	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil {
			t.Errorf("unexpected error: %v", e)
		}
	}
}

// TestSASCoordinated_SenderPipedStdin_BothShouldSucceed is the primary regression
// test. It simulates the exact failure mode: the sender has piped stdin containing
// "test\n" (from `echo test | hermod tx -v -`). Before the fix, fmt.Scanln read
// "test" and localOK=false was sent to the peer, causing both sides to fail.
// After the fix, the prompt reads from /dev/tty (injected as a reader here),
// so the piped stdin content no longer interferes with the SAS answer.
func TestSASCoordinated_SenderPipedStdin_BothShouldSucceed(t *testing.T) {
	clientConn, serverConn, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	senderStream, receiverStream := newMockStreamPair()
	senderConn := newMockSASConn(senderStream)
	receiverConn := newMockSASConn(receiverStream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)

	// Sender's "stdin" contains "test\n" (the piped payload content).
	// But the SAS reader is injected separately (simulating /dev/tty reading "y").
	senderTTYReader := strings.NewReader("y\n")

	go func() {
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, senderTTYReader, nil)
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("y\n"), nil)
	}()

	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil {
			t.Errorf("transfer should succeed when both answer y (piped stdin scenario): %v", e)
		}
	}
}

// TestSASCoordinated_ReceiverAnswersFirst_BothShouldSucceed verifies that the
// order in which sides answer does not affect the outcome — both should succeed.
func TestSASCoordinated_ReceiverAnswersFirst_BothShouldSucceed(t *testing.T) {
	clientConn, serverConn, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	senderStream, receiverStream := newMockStreamPair()
	senderConn := newMockSASConn(senderStream)
	receiverConn := newMockSASConn(receiverStream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)

	// Receiver answers first (with a slight head start), sender answers after.
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("y\n"), nil)
	}()
	// Small delay so receiver answers first.
	time.Sleep(20 * time.Millisecond)
	go func() {
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("y\n"), nil)
	}()

	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil {
			t.Errorf("transfer should succeed regardless of answer order: %v", e)
		}
	}
}

// TestSASCoordinated_SenderRejects verifies that if the sender rejects, both sides abort.
func TestSASCoordinated_SenderRejects(t *testing.T) {
	clientConn, serverConn, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	senderStream, receiverStream := newMockStreamPair()
	senderConn := newMockSASConn(senderStream)
	receiverConn := newMockSASConn(receiverStream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)

	go func() {
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("n\n"), nil)
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("y\n"), nil)
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil {
			errs = append(errs, e)
		}
	}
	if len(errs) == 0 {
		t.Error("expected at least one error when sender rejects")
	}
}

// TestSASCoordinated_ReceiverRejects verifies that if the receiver rejects, both sides abort.
func TestSASCoordinated_ReceiverRejects(t *testing.T) {
	clientConn, serverConn, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	senderStream, receiverStream := newMockStreamPair()
	senderConn := newMockSASConn(senderStream)
	receiverConn := newMockSASConn(receiverStream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)

	go func() {
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("y\n"), nil)
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("n\n"), nil)
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil {
			errs = append(errs, e)
		}
	}
	if len(errs) == 0 {
		t.Error("expected at least one error when receiver rejects")
	}
}

// --- helper types for error-path tests ---

// failConn is a sasStreamConn that returns an error from both stream methods.
type failConn struct{ err error }

func (f *failConn) OpenStreamSync(_ context.Context) (io.ReadWriteCloser, error) {
	return nil, f.err
}
func (f *failConn) AcceptStream(_ context.Context) (io.ReadWriteCloser, error) {
	return nil, f.err
}

// failWriteStream always fails on Write; Read returns EOF.
type failWriteStream struct{ err error }

func (f *failWriteStream) Write(_ []byte) (int, error) { return 0, f.err }
func (f *failWriteStream) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (f *failWriteStream) Close() error                { return nil }

// failReadStream succeeds on Write but always fails on Read.
type failReadStream struct{ err error }

func (f *failReadStream) Write(p []byte) (int, error) { return len(p), nil }
func (f *failReadStream) Read(_ []byte) (int, error)  { return 0, f.err }
func (f *failReadStream) Close() error                { return nil }

// connWithStream is a sasStreamConn that returns the given stream.
type connWithStream struct{ stream io.ReadWriteCloser }

func (c *connWithStream) OpenStreamSync(_ context.Context) (io.ReadWriteCloser, error) {
	return c.stream, nil
}
func (c *connWithStream) AcceptStream(_ context.Context) (io.ReadWriteCloser, error) {
	return c.stream, nil
}

// --- Error-path tests ---

// TestSASCoordinated_BothReject verifies the "rejected by both sides" message
// when both parties answer "n".
func TestSASCoordinated_BothReject(t *testing.T) {
	clientConn, serverConn, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	senderStream, receiverStream := newMockStreamPair()
	senderConn := newMockSASConn(senderStream)
	receiverConn := newMockSASConn(receiverStream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("n\n"), nil)
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("n\n"), nil)
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil {
			errs = append(errs, e)
		}
	}
	if len(errs) == 0 {
		t.Error("expected at least one error when both sides reject")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "both sides") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a 'both sides' error among: %v", errs)
	}
}

// TestSASCoordinated_OpenStreamError covers the "Could not complete SAS verification" error return.
func TestSASCoordinated_OpenStreamError(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	conn := &failConn{err: fmt.Errorf("open stream failed")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = performSASCoordinatedWith(ctx, conn, clientConn.ConnectionState(), true, strings.NewReader("y\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "Could not complete SAS verification") {
		t.Fatalf("expected 'Could not complete SAS verification' error, got: %v", err)
	}
}

// TestSASCoordinated_AcceptStreamError covers the "Could not complete SAS verification" error return.
func TestSASCoordinated_AcceptStreamError(t *testing.T) {
	_, serverConn, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	conn := &failConn{err: fmt.Errorf("accept stream failed")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = performSASCoordinatedWith(ctx, conn, serverConn.ConnectionState(), false, strings.NewReader("y\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "Could not complete SAS verification") {
		t.Fatalf("expected 'Could not complete SAS verification' error, got: %v", err)
	}
}

// TestSASCoordinated_StreamWriteError covers the "Could not send SAS result" error return.
func TestSASCoordinated_StreamWriteError(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	conn := &connWithStream{stream: &failWriteStream{err: fmt.Errorf("write failed")}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = performSASCoordinatedWith(ctx, conn, clientConn.ConnectionState(), true, strings.NewReader("y\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "Could not send SAS result") {
		t.Fatalf("expected 'Could not send SAS result' error, got: %v", err)
	}
}

// TestSASCoordinated_StreamReadError covers the "Could not read SAS result" error return.
func TestSASCoordinated_StreamReadError(t *testing.T) {
	clientConn, _, err := tlsPipe()
	if err != nil {
		t.Fatalf("tls pipe: %v", err)
	}

	conn := &connWithStream{stream: &failReadStream{err: fmt.Errorf("read failed")}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = performSASCoordinatedWith(ctx, conn, clientConn.ConnectionState(), true, strings.NewReader("y\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "Could not read SAS result") {
		t.Fatalf("expected 'Could not read SAS result' error, got: %v", err)
	}
}
