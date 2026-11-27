// Receiver-side payload routing: stdout, terminal, or temp-file save
// with parallel hashing.

package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mattn/go-isatty"
	"github.com/quic-go/quic-go"

	"github.com/hermod/hermod/pkg/transfer"
)

// receivePayload routes the incoming stream according to meta.Kind and destination.
// Returns the hex-encoded SHA-256, the number of bytes received, the temp file
// path (empty if no file was saved), and the final destination path (empty if
// no file was saved). Callers should pass isatty.IsTerminal(os.Stdout.Fd())
// for stdoutIsTTY.
func receivePayload(ctx context.Context, meta *transfer.Metadata, r io.Reader, destination string, stdoutIsTTY bool) (string, int64, string, string, error) {
	isStdoutTTY := stdoutIsTTY

	switch {
	case destination != "":
		// Always save to disk
		hash, tmpPath, destPath, n, err := saveToFile(ctx, r, meta, destination)
		return hash, n, tmpPath, destPath, err

	case !isStdoutTTY:
		// stdout is piped — stream bytes directly, computing hash in parallel.
		hash, n, err := transfer.HashStream(r, os.Stdout)
		return hash, n, "", "", err

	default:
		// Interactive terminal
		switch meta.Kind {
		case transfer.KindText, transfer.KindStream:
			// Print to stdout; no progress bar — bar escape codes on stderr
			// would corrupt text output on stdout.
			// Compute hash in parallel using TeeReader.
			h := sha256.New()
			n, err := io.Copy(os.Stdout, io.TeeReader(r, h))
			if err != nil {
				return "", 0, "", "", err
			}
			// Ensure KindText output ends with a newline so the shell prompt
			// starts on a new line. KindStream (piped stdin) already carries
			// the sender's trailing newline — adding another would create a
			// blank line.
			if meta.Kind == transfer.KindText {
				fmt.Fprint(os.Stdout, "\n")
			}
			logDebug("text payload written to stdout", "size_bytes", meta.Size)
			return fmt.Sprintf("%x", h.Sum(nil)), n, "", "", nil

		case transfer.KindFile:
			// Save to current directory using original filename
			hash, tmpPath, destPath, n, err := saveToFile(ctx, r, meta, ".")
			return hash, n, tmpPath, destPath, err
		}
	}
	return "", 0, "", "", nil
}

// saveToFile writes incoming payload to a temp file, then returns the temp
// path, computed hash, and bytes received. The caller is responsible for
// renaming the temp file to the final destination after verification.
// If meta.SHA256 is non-empty, it is verified against the computed hash; the
// temp file is removed on mismatch (backward-compatible with unit tests).
// If ctx is cancelled mid-transfer, the temp file is removed and an error is returned.
// Returns (computedHash, tempPath, destPath, bytesReceived, err).
func saveToFile(ctx context.Context, r io.Reader, meta *transfer.Metadata, destination string) (string, string, string, int64, error) {
	// Strip directory components from the remotely supplied name to prevent
	// path traversal. filepath.Base is the first line of defence;
	// SafeDestinationPath applies the same guard as a second layer.
	name := filepath.Base(meta.Name)
	if name == "" || name == "." || name == ".." {
		name = "received"
	}

	// Determine if destination is a dir or file path
	fi, err := os.Stat(destination)
	var destPath string
	if err == nil && fi.IsDir() {
		var sdpErr error
		destPath, sdpErr = transfer.SafeDestinationPath(destination, name)
		if sdpErr != nil {
			return "", "", "", 0, fmt.Errorf("resolve destination path: %w", sdpErr)
		}
	} else {
		destPath = destination
	}

	tmpPath := transfer.TempPath(destPath)
	// M4: create temp file with 0o600 permissions and O_EXCL to prevent
	// silently overwriting a stale temp from a previous crashed transfer.
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		// Stale temp file — remove and retry.
		if removeErr := os.Remove(tmpPath); removeErr != nil {
			return "", "", "", 0, fmt.Errorf("remove stale temp file: %w", removeErr)
		}
		f, err = os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	}
	if err != nil {
		return "", "", "", 0, fmt.Errorf("create temp file: %w", err)
	}

	// Ensure temp file is cleaned up on any error (including cancellation).
	var computedHash string
	var bytesReceived int64
	var copyErr error
	defer func() {
		if copyErr != nil {
			f.Close()
			os.Remove(tmpPath)
		}
	}()

	isTTY := isatty.IsTerminal(os.Stderr.Fd())
	var w io.Writer = f
	if isTTY && !quietMode && meta.Size > 0 {
		bar := newHashBar(meta.Size, "receiving")
		w = io.MultiWriter(f, bar)
	}

	// Compute hash in parallel while streaming to disk.
	computedHash, bytesReceived, copyErr = transfer.HashStream(r, w)
	if copyErr != nil {
		// Distinguish cancellation from copy failure.
		if ctx.Err() != nil || cancelledByPeer(copyErr) != nil {
			logDebug("transfer interrupted — temp file removed", "path", tmpPath)
			return "", "", "", 0, copyErr
		}
		return "", "", "", 0, fmt.Errorf("stream copy failed: %w", copyErr)
	}

	// Backward-compat: if meta.SHA256 was provided (e.g. unit tests), verify
	// it now. In the live protocol, meta.SHA256 is empty and the caller
	// verifies using the trailing hash stream.
	if meta.SHA256 != "" && computedHash != meta.SHA256 {
		copyErr = fmt.Errorf("sha256 mismatch: got %s, expected %s", computedHash, meta.SHA256)
		logError("Integrity check failed — file removed", "path", tmpPath, "err", copyErr)
		return "", "", "", 0, fmt.Errorf("integrity check failed: %w", copyErr)
	}

	if err := f.Close(); err != nil {
		copyErr = err
		return "", "", "", 0, fmt.Errorf("close temp file: %w", err)
	}
	logDebug("file hash computed", "sha256", computedHash, "bytes", bytesReceived)

	return computedHash, tmpPath, destPath, bytesReceived, nil
}

// finalizeTransfer verifies the received payload (byte count and trailing
// hash), renames the temp file after verification passes, and sends the
// completion ack. On any verification failure the temp file is removed —
// the rename has not happened yet, so removal is safe.
func finalizeTransfer(ctx context.Context, quicConn *quic.Conn, meta *transfer.Metadata, computedHash string, bytesReceived int64, tmpFile, destFile string) error {
	// removeSavedFile removes the temp file if one was saved.
	removeSavedFile := func() {
		if tmpFile != "" {
			os.Remove(tmpFile)
		}
	}

	// Verify received byte count against metadata when size is known.
	if meta.Size >= 0 && bytesReceived != meta.Size {
		removeSavedFile()
		logError("Downloaded byte count does not match expected — data may be incomplete or corrupted; retry the transfer",
			"expected", meta.Size, "received", bytesReceived)
		return fmt.Errorf("integrity check failed: expected %d bytes, received %d",
			meta.Size, bytesReceived)
	}

	// Accept the trailing hash stream sent by the sender after payload.
	// Missing or unreadable trailing hash is a fatal error — the file has not
	// been renamed yet, so removal is safe.
	logDebug("waiting for trailing hash stream from sender (stream 2)")
	hashStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		removeSavedFile()
		return fmt.Errorf("trailing hash stream unavailable: %w", err)
	}
	trailingHashBytes, hashErr := readLenPrefixedMax(hashStream, 256)
	hashStream.Close()
	if hashErr != nil {
		removeSavedFile()
		return fmt.Errorf("failed to read trailing hash: %w", hashErr)
	}

	senderHash := string(trailingHashBytes)
	logDebug("trailing hash received", "sha256", senderHash)
	if senderHash != computedHash {
		removeSavedFile()
		logError("Integrity check failed — sender's data fingerprint does not match the received data",
			"sender_sha256", senderHash, "computed_sha256", computedHash)
		fmt.Fprintf(os.Stderr, "Verification failed: the received data does not match what the sender transmitted. The transfer may have been corrupted — please retry.\n")
		return fmt.Errorf("integrity check failed: received data hash (%s) does not match sender hash (%s)",
			senderHash, computedHash)
	}
	logDebug("integrity check passed via trailing hash", "sha256", computedHash)

	// Rename the temp file to its final destination now that verification
	// passed. For non-file transfers tmpFile is empty.
	if tmpFile != "" && destFile != "" {
		if err := os.Rename(tmpFile, destFile); err != nil {
			return fmt.Errorf("finalize file: %w", err)
		}
		logInfo("File saved", "path", destFile, "size_bytes", bytesReceived)
		printStatus("Saved to %s", destFile)
	}

	// Signal sender that the transfer is complete before closing the connection.
	logDebug("sending acknowledgement to sender")
	ackStream, err := quicConn.OpenStreamSync(ctx)
	if err == nil {
		ackStream.Close()
		logDebug("acknowledgement sent")
	} else {
		logWarn("could not send acknowledgement to sender", "err", err)
	}
	return nil
}
