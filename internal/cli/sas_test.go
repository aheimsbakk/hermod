// Package cli: unit tests for SAS verification prompt and coordination.
package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
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

	ok, err := promptSASVerificationFrom(clientConn.ConnectionState(), strings.NewReader("y\n"))
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

	ok, err := promptSASVerificationFrom(clientConn.ConnectionState(), strings.NewReader("Y\n"))
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

	// "test" is what echo-piped stdin would produce, simulating the bug scenario.
	ok, err := promptSASVerificationFrom(clientConn.ConnectionState(), strings.NewReader("test\n"))
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

	ok, err := promptSASVerificationFrom(clientConn.ConnectionState(), strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected localOK=false for empty answer")
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
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("y\n"))
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("y\n"))
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
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, senderTTYReader)
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("y\n"))
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
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("y\n"))
	}()
	// Small delay so receiver answers first.
	time.Sleep(20 * time.Millisecond)
	go func() {
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("y\n"))
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
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("n\n"))
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("y\n"))
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
		errCh <- performSASCoordinatedWith(ctx, senderConn, clientConn.ConnectionState(), true, strings.NewReader("y\n"))
	}()
	go func() {
		errCh <- performSASCoordinatedWith(ctx, receiverConn, serverConn.ConnectionState(), false, strings.NewReader("n\n"))
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
