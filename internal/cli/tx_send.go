// Package cli: sender-side payload build and QUIC stream sequencing
// (metadata, payload, trailing hash, completion ack).

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/quic-go/quic-go"

	"github.com/hermod/hermod/pkg/transfer"
)

// buildPayload returns metadata and an io.Reader for the payload.
// SHA256 is always empty — the hash is computed during streaming and sent as
// trailing metadata. This avoids buffering large stdin inputs.
func buildPayload(input string, kind transfer.Kind, name string, isStdinPiped bool) (*transfer.Metadata, io.Reader, int64, error) {
	switch kind {
	case transfer.KindFile:
		fi, err := os.Stat(input)
		if err != nil {
			return nil, nil, 0, err
		}
		size := fi.Size()
		f, err := os.Open(input)
		if err != nil {
			return nil, nil, 0, err
		}
		// SHA256 intentionally empty — computed during streaming.
		meta := &transfer.Metadata{Kind: transfer.KindFile, Name: name, Size: size}
		return meta, f, size, nil

	case transfer.KindText:
		data := []byte(input)
		// SHA256 intentionally empty — computed during streaming.
		meta := &transfer.Metadata{Kind: transfer.KindText, Size: int64(len(data))}
		return meta, strings.NewReader(input), int64(len(data)), nil

	case transfer.KindStream:
		// Do not buffer stdin. Stream directly from os.Stdin while computing
		// hash in parallel via TeeReader in the send loop.
		// Size -1 signals unknown length to the progress bar logic.
		meta := &transfer.Metadata{Kind: transfer.KindStream, Size: -1}
		return meta, os.Stdin, -1, nil
	}
	return nil, nil, 0, fmt.Errorf("unknown payload kind: %s", kind)
}

// sendPayloadStreams writes metadata, payload, and the trailing hash over
// coordinated QUIC streams, then waits for the receiver's completion ack.
// SHA-256 is computed in parallel with the payload write via TeeReader; the
// hex digest is sent after the payload so the receiver can verify integrity.
func sendPayloadStreams(ctx context.Context, quicConn *quic.Conn, meta *transfer.Metadata, reader io.Reader, size int64) error {
	// Open metadata stream
	logDebug("opening QUIC metadata stream (stream 0)")
	metaStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open metadata stream: %w", err)
	}

	metaBytes, err := transfer.EncodeMetadata(meta)
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	if _, err := metaStream.Write(appendLenPrefix(metaBytes)); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	metaStream.Close()
	logDebug("metadata sent", "bytes", len(metaBytes))

	// Open payload stream
	logDebug("opening QUIC payload stream (stream 1)")
	payloadStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open payload stream: %w", err)
	}

	// Stream payload while computing SHA-256 in parallel via TeeReader.
	logInfo("Sending payload", "kind", meta.Kind, "size_bytes", meta.Size)
	isTTY := isatty.IsTerminal(os.Stderr.Fd())
	var payloadHash string
	// lineTerminated tracks whether the last output line already has a trailing
	// \n. When true, the cancel handler must NOT print another \n to avoid
	// creating a blank line before the error message.
	lineTerminated := true
	if isTTY && !quietMode && size > 0 {
		bar := newHashBar(size, "sending")
		dest := io.MultiWriter(payloadStream, bar)
		payloadHash, _, err = transfer.HashStream(reader, dest)
		lineTerminated = false // hash bar uses \r, needs \n on cancel
	} else if isTTY && !quietMode && size < 0 {
		// Unknown size (stream): bouncing "###" bar that resizes with the terminal.
		bar := newStreamBar()
		dest := io.MultiWriter(payloadStream, bar)
		payloadHash, _, err = transfer.HashStream(reader, dest)
		bar.Finish() // prints \n, terminating the bar line
		lineTerminated = true
	} else {
		payloadHash, _, err = transfer.HashStream(reader, payloadStream)
	}
	if err != nil {
		if peerErr := cancelledByPeer(err); peerErr != nil {
			if !quietMode && !lineTerminated {
				fmt.Fprint(os.Stderr, "\n")
			}
			return peerErr
		}
		if ctx.Err() != nil {
			if !quietMode && !lineTerminated {
				fmt.Fprint(os.Stderr, "\n")
			}
			return fmt.Errorf("You cancelled the transfer.")
		}
		return fmt.Errorf("send payload: %w", err)
	}
	// Payload send succeeded — bar line is terminated (OnCompletion for hash
	// bar, bar.Finish() for stream bar, or no bar at all).
	lineTerminated = true
	payloadStream.Close()
	logDebug("payload stream closed — all bytes sent", "sha256", payloadHash)

	// Send trailing hash stream (stream 2). The receiver verifies the hash of
	// the received data against this value after draining the payload.
	logDebug("opening QUIC trailing hash stream (stream 2)")
	hashStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open trailing hash stream: %w", err)
	}
	if _, err := hashStream.Write(appendLenPrefix([]byte(payloadHash))); err != nil {
		return fmt.Errorf("write trailing hash: %w", err)
	}
	hashStream.Close()
	logDebug("trailing hash sent", "sha256", payloadHash)

	// Wait for receiver to signal it has finished reading before closing the connection.
	// This prevents the QUIC connection from closing before rx accepts the streams.
	logDebug("waiting for receiver acknowledgement")
	ackStream, err := quicConn.AcceptStream(ctx)
	if err == nil {
		ackStream.Close()
		logDebug("acknowledgement received from receiver")
	} else {
		if peerErr := cancelledByPeer(err); peerErr != nil {
			if !quietMode && !lineTerminated {
				fmt.Fprint(os.Stderr, "\n")
			}
			return peerErr
		}
		logWarn("Did not receive acknowledgement from receiver — transfer may still have succeeded", "err", err)
	}
	return nil
}
