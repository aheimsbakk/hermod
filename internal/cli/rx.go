// Package cli: rx (receive) command.
package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/crypto"
	"github.com/hermod/hermod/internal/network"
	"github.com/hermod/hermod/pkg/transfer"
)

func newRxCmd() *cobra.Command {
	var (
		destination string
		serverURL   string
		verify      bool
		listenUDP   string
	)

	cmd := &cobra.Command{
		Use:     "rx [CODE]",
		Aliases: []string{"receive"},
		Short:   "Receive a payload using a transfer code",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRx(args[0], destination, serverURL, verify, listenUDP, cmd.Flags().Changed("server"))
		},
	}

	cmd.Flags().StringVarP(&destination, "destination", "d", envOrDefault("HERMOD_DEST_DIR", ""), "Output directory or file path")
	cmd.Flags().StringVarP(&serverURL, "server", "s", configServerURL(), "Signaling server URL")
	cmd.Flags().BoolVarP(&verify, "verify", "v", false, "Enforce SAS out-of-band verification")
	cmd.Flags().StringVarP(&listenUDP, "listen", "l", envOrDefault("HERMOD_LISTEN", ":0"), "Local UDP bind address")

	return cmd
}

func runRx(code, destination, serverURL string, verify bool, listenUDP string, saveServer bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logDebug("loading config")
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	if saveServer && serverURL != cfg.ServerURL {
		config.SetDefaultServer(cfg, serverURL)
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("save configuration: %w", err)
		}
		printStatus("Default server set to %s", serverURL)
		logInfo("Default server updated", "server", serverURL)
	}

	// Parse transfer code
	logDebug("parsing transfer code")
	channelID, words, err := crypto.ParseTransferCode(code)
	if err != nil {
		return fmt.Errorf("parse transfer code: %w", err)
	}
	password := strings.Join(words, "-")
	logDebug("transfer code parsed", "channel_id", channelID)

	// Generate ephemeral TLS cert
	logDebug("generating ephemeral TLS certificate for QUIC")
	epCert, epKey, epCertDER, err := generateEphemeralCert()
	if err != nil {
		return fmt.Errorf("generate ephemeral certificate: %w", err)
	}
	myFP := network.CertFingerprint(epCertDER)
	logDebug("ephemeral certificate generated", "fingerprint", myFP)

	// Enforce server trust — abort before any network call if the server
	// certificate has not been pinned via 'hermod trust'.
	logDebug("checking pinned fingerprint for server", "server", serverURL)
	pinnedFP, err := requireTrustedServer(cfg, serverURL)
	if err != nil {
		return err
	}

	// Connect to signaling server
	sigFamily := network.IPFamilyAny
	switch {
	case ipv4Only:
		sigFamily = network.IPFamilyV4
	case ipv6Only:
		sigFamily = network.IPFamilyV6
	}
	logInfo("Connecting to signaling server", "server", serverURL)
	sigRaw, err := network.DialSignalingWithFamily(serverURL, pinnedFP, sigFamily)
	if err != nil {
		return fmt.Errorf("connect to signaling server: %w", err)
	}
	defer sigRaw.Close()
	sig := sigRaw.WithContext(ctx)
	logDebug("WebSocket connection to signaling server established")

	// Join channel
	logDebug("joining channel on signaling server", "channel_id", channelID)
	publicIPV4, publicIPV6, err := sig.Join(channelID)
	if err != nil {
		return fmt.Errorf("join channel: %w", err)
	}
	logInfo("Joined channel", "channel_id", channelID, "public_ipv4", publicIPV4, "public_ipv6", publicIPV6)

	// Bind UDP socket
	// Override the listen address to enforce strict IP family when -4/-6 is set.
	bindAddr := listenUDP
	if ipv4Only && listenUDP == ":0" {
		bindAddr = "0.0.0.0:0"
	} else if ipv6Only && listenUDP == ":0" {
		bindAddr = "[::]:0"
	}
	logDebug("binding UDP socket", "addr", bindAddr)
	udpConn, err := network.BindUDP(bindAddr)
	if err != nil {
		return fmt.Errorf("bind UDP socket: %w", err)
	}
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()

	localAddr, err := network.LocalUDPAddr(udpConn)
	if err != nil {
		return fmt.Errorf("get local UDP address: %w", err)
	}
	logDebug("UDP socket bound", "local_addr", localAddr.String())

	// CPace init (receiver role)
	logDebug("initialising CPace PAKE handshake", "role", "receiver")
	cpaceSession, myPubMsg, err := crypto.CPaceInit(password, channelID, "receiver")
	if err != nil {
		return fmt.Errorf("initialize CPace handshake: %w", err)
	}

	// Exchange CPace messages
	logDebug("waiting for sender CPace public message from relay")
	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("receive CPace message from peer: %w", err)
	}
	peerCPaceMsg, err := network.DecodeCPaceMsg(peerCPaceMsgBytes)
	if err != nil {
		return fmt.Errorf("decode peer cpace msg: %w", err)
	}
	logDebug("sender CPace message received and decoded")

	logDebug("sending CPace public message to peer via relay")
	cpaceMsgBytes, err := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	if err != nil {
		return fmt.Errorf("encode CPace message: %w", err)
	}
	if err := sig.SendBlob(channelID, cpaceMsgBytes); err != nil {
		return fmt.Errorf("send CPace message: %w", err)
	}

	// Finish CPace
	logDebug("completing CPace handshake to derive shared key")
	kClassical, err := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)
	if err != nil {
		return fmt.Errorf("complete CPace handshake: %w", err)
	}
	logInfo("PAKE handshake complete — shared key established")

	// Receive sender's bundle
	logDebug("waiting for sender endpoint bundle from relay")
	encSenderBundle, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("receive endpoint bundle from sender: %w", err)
	}
	senderBundleBytes, err := crypto.OpenAAD(kClassical, channelIDAad(channelID), encSenderBundle)
	if err != nil {
		return fmt.Errorf("decrypt sender endpoint bundle: %w", err)
	}
	senderBundle, err := network.DecodeEndpointBundle(senderBundleBytes)
	if err != nil {
		return fmt.Errorf("decode sender endpoint bundle: %w", err)
	}
	logDebug("sender endpoint bundle received",
		"public_v4", senderBundle.PublicEndpointV4,
		"public_v6", senderBundle.PublicEndpointV6,
		"local_v4_count", len(senderBundle.LocalEndpointsV4),
		"local_v6_count", len(senderBundle.LocalEndpointsV6),
		"require_verify", senderBundle.RequireVerify,
	)

	// Enforce verification symmetrically: if either side requires it, both must do it.
	if !verify && senderBundle.RequireVerify {
		logInfo("Sender requested SAS verification — enabling for this transfer")
	}
	verify = verify || senderBundle.RequireVerify

	// Send our bundle (dual-stack)
	ipFamily := network.IPFamilyAny
	switch {
	case ipv4Only:
		ipFamily = network.IPFamilyV4
	case ipv6Only:
		ipFamily = network.IPFamilyV6
	}
	localV4, localV6, err := network.LocalEndpoints(localAddr.Port, ipFamily)
	if err != nil {
		localV4, localV6 = nil, nil
		logWarn("could not enumerate local network interfaces — using public endpoint only", "err", err)
	}
	portStr := fmt.Sprintf("%d", localAddr.Port)
	var publicEPV4, publicEPV6 string
	if publicIPV4 != "" && ipFamily != network.IPFamilyV6 {
		publicEPV4 = net.JoinHostPort(publicIPV4, portStr)
	}
	if publicIPV6 != "" && ipFamily != network.IPFamilyV4 {
		publicEPV6 = net.JoinHostPort(publicIPV6, portStr)
	}
	logDebug("local endpoints collected", "local_v4", localV4, "local_v6", localV6, "public_v4", publicEPV4, "public_v6", publicEPV6)

	myBundle := network.EndpointBundle{
		LocalEndpointsV4: localV4,
		LocalEndpointsV6: localV6,
		PublicEndpointV4: publicEPV4,
		PublicEndpointV6: publicEPV6,
		CertFingerprint:  myFP,
		RequireVerify:    verify,
	}
	myBundleBytes, err := network.EncodeEndpointBundle(myBundle)
	if err != nil {
		return fmt.Errorf("encode endpoint bundle: %w", err)
	}
	encMyBundle, err := crypto.SealAAD(kClassical, channelIDAad(channelID), myBundleBytes)
	if err != nil {
		return fmt.Errorf("encrypt endpoint bundle: %w", err)
	}
	logDebug("endpoint bundle encrypted and sending to sender via relay")
	if err := sig.SendBlob(channelID, encMyBundle); err != nil {
		return fmt.Errorf("send endpoint bundle: %w", err)
	}

	// Build candidate lists from sender's bundle, split by address family.
	candidatesV4, err := network.ParseCandidates(senderBundle.CandidatesV4())
	if err != nil {
		return fmt.Errorf("parse IPv4 candidates: %w", err)
	}
	candidatesV6, err := network.ParseCandidates(senderBundle.CandidatesV6())
	if err != nil {
		return fmt.Errorf("parse IPv6 candidates: %w", err)
	}
	// Enforce IP family flag: clear candidates from the wrong family so
	// HolePunchDual only tries addresses matching -4/-6.
	switch ipFamily {
	case network.IPFamilyV4:
		candidatesV6 = nil
	case network.IPFamilyV6:
		candidatesV4 = nil
	}
	logDebug("NAT candidates parsed", "v4_count", len(candidatesV4), "v6_count", len(candidatesV6))

	// Create a probe context that outlives HolePunch so probing continues
	// until the QUIC connection is established, preventing NAT mappings from
	// expiring in the gap between hole-punch return and QUIC handshake.
	probeCtx, probeCancel := context.WithCancel(ctx)
	defer probeCancel()

	logInfo("Starting UDP hole punch", "v4_candidates", len(candidatesV4), "v6_candidates", len(candidatesV6))
	printStatus("Establishing P2P connection...")
	punchResult, err := network.HolePunchDual(ctx, probeCtx, mux, candidatesV4, candidatesV6, holePunchNonce(kClassical))
	if err != nil {
		return fmt.Errorf("UDP hole punch: %w", err)
	}
	logInfo("UDP hole punch succeeded", "peer_addr", punchResult.PeerAddr.String())

	// QUIC listen (receiver = QUIC server)
	logDebug("starting QUIC listener for incoming sender connection")
	tlsCert := buildTLSCert(epCertDER, epKey, epCert)
	baseTLS := config.BuildTLSConfig(cfg)
	ln, err := network.ListenQUIC(mux, tlsCert, baseTLS, senderBundle.CertFingerprint)
	if err != nil {
		return fmt.Errorf("QUIC listen: %w", err)
	}
	defer ln.Close()

	logDebug("waiting for sender to establish QUIC connection")
	quicConn, err := ln.Accept(ctx)
	if err != nil {
		return fmt.Errorf("QUIC accept: %w", err)
	}
	defer quicConn.CloseWithError(0, "done")
	// Stop probing — QUIC keepalive will maintain the NAT mapping from now on.
	probeCancel()
	logInfo("QUIC connection accepted from sender")

	// Watch for Ctrl+C: close the connection so the sender is notified immediately.
	go func() {
		<-ctx.Done()
		quicConn.CloseWithError(cancelCodeUser, cancelMsgReceiver)
	}()

	// SAS verification
	if verify {
		logInfo("Starting SAS out-of-band verification")
		quicState := quicConn.ConnectionState()
		if err := performSASCoordinated(ctx, quicConn, quicState.TLS, false, channelIDAad(channelID)); err != nil {
			return err
		}
		logInfo("SAS verification passed")
	}

	// Read metadata stream
	logDebug("waiting for metadata stream from sender (stream 0)")
	metaStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept metadata stream: %w", err)
	}
	metaBytes, err := readLenPrefixed(metaStream)
	if err != nil {
		return fmt.Errorf("read metadata: %w", err)
	}
	metaStream.Close()

	meta, err := transfer.DecodeMetadata(metaBytes)
	if err != nil {
		return fmt.Errorf("decode metadata: %w", err)
	}
	logInfo("Metadata received", "kind", meta.Kind, "name", meta.Name, "size_bytes", meta.Size)
	logDebug("metadata detail", "sha256", meta.SHA256)

	// Accept payload stream
	logDebug("waiting for payload stream from sender (stream 1)")
	payloadStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept payload stream: %w", err)
	}
	defer payloadStream.Close()

	logInfo("Receiving payload", "kind", meta.Kind, "size_bytes", meta.Size)
	computedHash, err := receivePayload(ctx, meta, payloadStream, destination, isatty.IsTerminal(os.Stdout.Fd()))
	if err != nil {
		if peerErr := cancelledByPeer(err); peerErr != nil {
			if !quietMode {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by sender.\n")
			}
			return peerErr
		}
		if ctx.Err() != nil {
			if !quietMode {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by receiver.\n")
			}
			return fmt.Errorf("transfer cancelled")
		}
		return err
	}

	// Accept the trailing hash stream sent by the sender after payload (M-07).
	logDebug("waiting for trailing hash stream from sender (stream 2)")
	hashStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		logWarn("could not accept trailing hash stream — skipping integrity check", "err", err)
	} else {
		trailingHashBytes, hashErr := readLenPrefixed(hashStream)
		hashStream.Close()
		if hashErr != nil {
			logWarn("could not read trailing hash — skipping integrity check", "err", hashErr)
		} else {
			senderHash := string(trailingHashBytes)
			logDebug("trailing hash received", "sha256", senderHash)
			if senderHash != computedHash {
				logError("Integrity check failed — sender hash does not match received data",
					"sender_sha256", senderHash, "computed_sha256", computedHash)
				fmt.Fprintf(os.Stderr, "Verification failed: received data does not match sender hash.\n")
				return fmt.Errorf("integrity check failed: received data hash (%s) does not match sender hash (%s)",
					senderHash, computedHash)
			}
			logDebug("integrity check passed via trailing hash", "sha256", computedHash)
		}
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

	logInfo("Transfer complete", "kind", meta.Kind, "size_bytes", meta.Size)
	printStatus("Receive and verification complete.")
	return nil
}

// receivePayload routes the incoming stream according to meta.Kind and destination.
// Returns the hex-encoded SHA-256 of the received data computed in parallel
// during the transfer (M-07). stdoutIsTTY must be true when os.Stdout is a
// real terminal; callers should pass isatty.IsTerminal(os.Stdout.Fd()).
func receivePayload(ctx context.Context, meta *transfer.Metadata, r io.Reader, destination string, stdoutIsTTY bool) (string, error) {
	isStdoutTTY := stdoutIsTTY

	switch {
	case destination != "":
		// Always save to disk
		return saveToFile(ctx, r, meta, destination)

	case !isStdoutTTY:
		// stdout is piped — stream bytes directly, computing hash in parallel.
		hash, err := transfer.HashStream(r, os.Stdout)
		return hash, err

	default:
		// Interactive terminal
		switch meta.Kind {
		case transfer.KindText, transfer.KindStream:
			// Print to stdout; no progress bar — bar escape codes on stderr
			// would corrupt text output on stdout.
			// Compute hash in parallel using TeeReader.
			h := sha256.New()
			if _, err := io.Copy(os.Stdout, io.TeeReader(r, h)); err != nil {
				return "", err
			}
			// Ensure KindText output ends with a newline so the shell prompt
			// starts on a new line. KindStream (piped stdin) already carries
			// the sender's trailing newline — adding another would create a
			// blank line.
			if meta.Kind == transfer.KindText {
				fmt.Fprint(os.Stdout, "\n")
			}
			logDebug("text payload written to stdout", "size_bytes", meta.Size)
			return fmt.Sprintf("%x", h.Sum(nil)), nil

		case transfer.KindFile:
			// Save to current directory using original filename
			return saveToFile(ctx, r, meta, ".")
		}
	}
	return "", nil
}

// saveToFile writes incoming payload to a temp file, then renames.
// If meta.SHA256 is non-empty, it is verified against the computed hash; the
// temp file is removed on mismatch (backward-compatible with unit tests).
// In the new protocol, meta.SHA256 is empty and verification is done by the
// caller using the sender's trailing hash stream (M-07).
// Returns the hex-encoded SHA-256 of the received data.
// If ctx is cancelled mid-transfer, the temp file is removed and an error is returned.
func saveToFile(ctx context.Context, r io.Reader, meta *transfer.Metadata, destination string) (string, error) {
	// Strip directory components from the remotely supplied name to prevent
	// path traversal (C-01). filepath.Base is the first line of defence;
	// SafeDestinationPath applies the same guard as a second layer.
	name := filepath.Base(meta.Name)
	if name == "" || name == "." || name == ".." {
		name = "received"
	}

	// Determine if destination is a dir or file path
	fi, err := os.Stat(destination)
	var destPath string
	if err == nil && fi.IsDir() {
		destPath = transfer.SafeDestinationPath(destination, name)
	} else {
		destPath = destination
	}

	tmpPath := transfer.TempPath(destPath)
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}

	// Ensure temp file is cleaned up on any error (including cancellation).
	var computedHash string
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

	// Compute hash in parallel while streaming to disk (M-07).
	computedHash, copyErr = transfer.HashStream(r, w)
	if copyErr != nil {
		// Distinguish cancellation from copy failure.
		if ctx.Err() != nil || cancelledByPeer(copyErr) != nil {
			logDebug("transfer interrupted — temp file removed", "path", tmpPath)
			return "", copyErr
		}
		return "", fmt.Errorf("stream copy failed: %w", copyErr)
	}

	// Backward-compat: if meta.SHA256 was provided (e.g. unit tests), verify
	// it now. In the live protocol, meta.SHA256 is empty and the caller
	// verifies using the trailing hash stream (M-07).
	if meta.SHA256 != "" && computedHash != meta.SHA256 {
		copyErr = fmt.Errorf("sha256 mismatch: got %s, expected %s", computedHash, meta.SHA256)
		logError("Integrity check failed — file removed", "path", tmpPath, "err", copyErr)
		return "", fmt.Errorf("integrity check failed: %w", copyErr)
	}

	if err := f.Close(); err != nil {
		copyErr = err
		return "", fmt.Errorf("close temp file: %w", err)
	}
	logDebug("file hash computed", "sha256", computedHash)

	if err := os.Rename(tmpPath, destPath); err != nil {
		copyErr = err
		return "", fmt.Errorf("finalize file: %w", err)
	}

	logInfo("File saved", "path", destPath, "size_bytes", meta.Size)
	printStatus("Saved to %s", destPath)
	return computedHash, nil
}

// readLenPrefixed reads a 4-byte big-endian length-prefixed message from r.
func readLenPrefixed(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > 1<<20 { // 1 MiB sanity limit for metadata
		return nil, fmt.Errorf("metadata too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return buf, nil
}

// silence unused import for bufio — used in tx.go.
var _ = bufio.NewReader
