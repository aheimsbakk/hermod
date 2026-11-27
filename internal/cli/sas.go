// SAS (Short Authentication String) out-of-band verification: prompt,
// identicon, and the 1-byte confirm exchange over a dedicated QUIC stream.

package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/quic-go/quic-go"

	"github.com/hermod/hermod/internal/crypto"
)

// openTTYFunc is the provider used to open the controlling terminal for SAS
// prompts.  It defaults to openTTY and may be replaced in tests to inject a
// pipe without a real terminal.
var openTTYFunc = openTTY

// sasStreamConn is the subset of *quic.Conn used for SAS stream coordination.
// Using io.ReadWriteCloser for streams makes the interface testable without quic-go.
type sasStreamConn interface {
	OpenStreamSync(ctx context.Context) (io.ReadWriteCloser, error)
	AcceptStream(ctx context.Context) (io.ReadWriteCloser, error)
}

// quicSASConn adapts *quic.Conn to sasStreamConn.
type quicSASConn struct{ conn *quic.Conn }

func (q *quicSASConn) OpenStreamSync(ctx context.Context) (io.ReadWriteCloser, error) {
	return q.conn.OpenStreamSync(ctx)
}
func (q *quicSASConn) AcceptStream(ctx context.Context) (io.ReadWriteCloser, error) {
	return q.conn.AcceptStream(ctx)
}

// errSASCancelledByPeer is the context-cause sentinel emitted when the peer
// drops the QUIC connection during SAS verification.
var errSASCancelledByPeer = errors.New("the other side cancelled SAS verification.")

// performSASCoordinated shows the SAS prompt, then exchanges a 1-byte
// confirmation with the peer over a dedicated QUIC stream. Both sides must
// confirm; if either rejects, the transfer is aborted.
//
// isSender=true: sender opens the SAS stream (QUIC client role).
// isSender=false: receiver accepts the SAS stream (QUIC server role).
//
// sasContext is bound into TLS ExportKeyingMaterial to couple the SAS to the
// specific session (L-01). Pass the channel ID bytes.
// User input is read from /dev/tty so that piped stdin does not interfere.
func performSASCoordinated(ctx context.Context, conn *quic.Conn, tlsState tls.ConnectionState, isSender bool, sasContext []byte) error {
	tty, err := openTTYFunc()
	if err != nil {
		return fmt.Errorf("open tty for SAS prompt: %w", err)
	}
	defer tty.Close()

	// Derive a cancellable context so we can propagate the peer disconnect
	// as a context cancellation. This lets promptSASVerificationFrom return
	// cleanly (with a newline) instead of leaving the prompt text and error
	// on the same line.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	// Unblock the prompt read if the local operation is cancelled (SIGINT)
	// or the peer drops the connection.
	go func() {
		select {
		case <-ctx.Done():
			// local user cancelled (SIGINT) — cancel(nil) from defer
		case <-conn.Context().Done():
			// peer dropped the connection — tag the cause so we can
			// distinguish it from a local SIGINT in the error message.
			cancel(errSASCancelledByPeer)
		}
		tty.Close()
	}()

	return performSASCoordinatedWith(ctx, &quicSASConn{conn}, tlsState, isSender, tty, sasContext)
}

// cancelMessage returns the user-facing message for a SAS cancellation
// based on whether the local user or the remote side cancelled.
func cancelMessage(ctx context.Context) string {
	if errors.Is(context.Cause(ctx), errSASCancelledByPeer) {
		return "The other side cancelled SAS verification."
	}
	return "You cancelled SAS verification."
}

// performSASCoordinatedWith is the injectable core used by tests.
func performSASCoordinatedWith(ctx context.Context, conn sasStreamConn, tlsState tls.ConnectionState, isSender bool, reader io.Reader, sasContext []byte) error {
	// Show prompt and collect local answer first.
	localOK, err := promptSASVerificationFrom(ctx, tlsState, reader, sasContext)
	cancelled := false
	if err != nil {
		if errors.Is(err, context.Canceled) {
			cancelled = true
			localOK = false
		} else {
			return err
		}
	}

	var localByte byte
	if localOK {
		localByte = 0x01
	}

	var stream io.ReadWriteCloser
	if isSender {
		stream, err = conn.OpenStreamSync(ctx)
		if err != nil {
			if cancelled {
				return errors.New(cancelMessage(ctx))
			}
			return fmt.Errorf("failed to complete SAS verification: %w", err)
		}
	} else {
		stream, err = conn.AcceptStream(ctx)
		if err != nil {
			if cancelled {
				return errors.New(cancelMessage(ctx))
			}
			return fmt.Errorf("failed to complete SAS verification: %w", err)
		}
	}
	defer stream.Close()

	// Both sides write their result first, then read the peer's result.
	// This avoids deadlock on a bidirectional stream.
	if _, err := stream.Write([]byte{localByte}); err != nil {
		if cancelled {
			return errors.New(cancelMessage(ctx))
		}
		return fmt.Errorf("failed to send SAS result to the other side: %w", err)
	}

	var peerBuf [1]byte
	if _, err := io.ReadFull(stream, peerBuf[:]); err != nil {
		if cancelled {
			return errors.New(cancelMessage(ctx))
		}
		return fmt.Errorf("failed to read SAS result from the other side: %w", err)
	}

	switch {
	case cancelled && peerBuf[0] != 0x01:
		logInfo("SAS verification failed", "reason", cancelMessage(ctx))
		return errors.New(cancelMessage(ctx))
	case cancelled:
		logInfo("SAS verification failed", "reason", cancelMessage(ctx))
		return errors.New(cancelMessage(ctx))
	case !localOK && peerBuf[0] != 0x01:
		logInfo("SAS verification failed", "reason", "both sides rejected")
		return fmt.Errorf("Both sides rejected the out-of-band security verification — connection aborted. Retry and ensure the phrase matches on both ends.")
	case !localOK:
		logInfo("SAS verification failed", "reason", "local user rejected")
		return fmt.Errorf("You rejected the out-of-band security verification — connection aborted.")
	case peerBuf[0] != 0x01:
		logInfo("SAS verification failed", "reason", "peer rejected")
		return fmt.Errorf("The other side rejected the out-of-band security verification — connection aborted.")
	}
	logInfo("SAS verification confirmed")
	return nil
}

// promptSASVerificationFrom shows the SAS + identicon and reads the answer from r.
// sasContext is bound into TLS ExportKeyingMaterial to couple the SAS to the
// specific session (L-01). Pass the channel ID bytes; nil is accepted.
// Separating the reader makes this testable without a real terminal.
func promptSASVerificationFrom(ctx context.Context, tlsState tls.ConnectionState, r io.Reader, sasContext []byte) (bool, error) {
	material, err := tlsState.ExportKeyingMaterial("hermod-sas-v1", sasContext, 32)
	if err != nil {
		return false, fmt.Errorf("export keying material: %w", err)
	}

	words := crypto.SASFromBytes(material)
	fmt.Fprintf(os.Stderr, "=== Out-of-Band Verification ===\n")
	fmt.Fprintf(os.Stderr, "SAS: %s\n", strings.Join(words, " "))
	identicon, err := crypto.Identicon(material[:16])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not render identicon: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", identicon)
	}
	fmt.Fprint(os.Stderr, "Compare these values with the other end. Do they match? [y/N]: ")

	ch := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(r)
		if scanner.Scan() {
			ch <- scanner.Text()
		}
		close(ch)
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "")
		return false, ctx.Err()
	case text, ok := <-ch:
		if !ok {
			// If the reader closed because the context was cancelled
			// (e.g. tty.Close() in performSASCoordinated), return the
			// context error so the caller can set cancelled=true.
			if errors.Is(ctx.Err(), context.Canceled) {
				fmt.Fprintln(os.Stderr, "")
				return false, ctx.Err()
			}
			// Reader closed without context cancellation (e.g. peer
			// dropped the connection before our cancellation handled
			// it). Print a newline so the prompt text is not on the
			// same line as the error message.
			fmt.Fprintln(os.Stderr, "")
			return false, nil
		}
		answer := strings.TrimSpace(text)
		return answer == "y" || answer == "Y", nil
	}
}
