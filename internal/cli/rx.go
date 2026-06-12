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
	"time"

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
	sigRaw, err := network.DialSignalingWithFamily(ctx, serverURL, pinnedFP, sigFamily)
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

	// Discover external UDP address via the signaling server's reflection
	// endpoint BEFORE wrapping the conn in the mux. The mux's readLoop
	// would consume the reflection response, so we must do this on the
	// raw conn.
	var discoveredAddr *net.UDPAddr
	if discovered, err := discoverExternalAddr(ctx, serverURL, udpConn, 2*time.Second); err != nil {
		logDebug("external UDP address discovery failed — using server-reported IP", "err", err)
	} else {
		discoveredAddr = discovered
		logDebug("external UDP address discovered", "addr", discoveredAddr.String())
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

	// Generate X25519 key pair + ML-KEM receiver key for hybrid KEM
	logDebug("generating X25519 + ML-KEM-768 key pairs")
	x25519Priv, x25519Pub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("generate X25519 key pair: %w", err)
	}
	mlkemKeys, err := crypto.GenerateMLKEMReceiverKey()
	if err != nil {
		return fmt.Errorf("generate ML-KEM key pair: %w", err)
	}

	// Receive sender's blob 1: CPace + X25519 pub
	logDebug("waiting for sender hybrid handshake blob 1 from relay")
	blob1, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("receive sender handshake blob 1: %w", err)
	}
	peerCPacePub, peerX25519Pub, err := network.ParseSenderHandshakeBlob(blob1)
	if err != nil {
		return fmt.Errorf("parse sender handshake blob: %w", err)
	}
	logDebug("sender handshake blob 1 received and parsed")

	// Finish CPace
	logDebug("completing CPace handshake to derive shared key")
	kClassical, err := cpaceSession.CPaceFinish(peerCPacePub)
	if err != nil {
		return fmt.Errorf("complete CPace handshake: %w", err)
	}
	logInfo("PAKE handshake complete — shared key established")

	// X25519 ECDH shared secret (before sending blob 2, so we can send immediately)
	logDebug("computing X25519 ECDH shared secret")
	peerX25519Key, err := crypto.NewX25519PubFromBytes(peerX25519Pub)
	if err != nil {
		return fmt.Errorf("parse sender X25519 public key: %w", err)
	}
	ssX25519, err := crypto.ECDHX25519(x25519Priv, peerX25519Key)
	if err != nil {
		return fmt.Errorf("X25519 ECDH: %w", err)
	}

	// Send blob 2: CPace + X25519 pub + ML-KEM enc key (binary)
	logDebug("sending hybrid handshake blob 2 (CPace + X25519 + MLKEM ek) via relay")
	blob2 := network.ReceiverHandshakeBlob(myPubMsg, x25519Pub, mlkemKeys.EncapKeyBytes())
	if err := sig.SendBlob(channelID, blob2); err != nil {
		return fmt.Errorf("send hybrid handshake blob 2: %w", err)
	}

	// Receive blob 3: KEM ciphertext + encrypted sender bundle
	logDebug("waiting for sender bundle blob 3 (KEM ct + enc bundle) from relay")
	blob3, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("receive sender bundle blob 3: %w", err)
	}
	kemCt, encSenderBundle, err := network.ParseSenderBundleBlob(blob3)
	if err != nil {
		return fmt.Errorf("parse sender bundle blob: %w", err)
	}

	// ML-KEM decapsulation
	logDebug("decapsulating ML-KEM-768 shared secret")
	ssMLKEM, err := crypto.DecapsulateMLKEM(mlkemKeys.DecapKey, kemCt)
	if err != nil {
		return fmt.Errorf("ML-KEM decapsulation: %w", err)
	}

	// Derive hybrid blob key
	logDebug("deriving hybrid blob key from CPace + X25519 + ML-KEM")
	hybridKey := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)

	// Decrypt sender's bundle with hybrid key
	senderBundleBytes, err := crypto.OpenAAD(hybridKey, channelIDAad(channelID), encSenderBundle)
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
	var publicEPV4, publicEPV6 string
	if discoveredAddr != nil {
		// Use the discovered external UDP address (CGNAT-aware).
		if discoveredAddr.IP.To4() != nil && ipFamily != network.IPFamilyV6 {
			publicEPV4 = discoveredAddr.String()
		} else if ipFamily != network.IPFamilyV4 {
			publicEPV6 = discoveredAddr.String()
		}
	} else {
		// Fall back to server-reported IP + local port.
		portStr := fmt.Sprintf("%d", localAddr.Port)
		if publicIPV4 != "" && ipFamily != network.IPFamilyV6 {
			publicEPV4 = net.JoinHostPort(publicIPV4, portStr)
		}
		if publicIPV6 != "" && ipFamily != network.IPFamilyV4 {
			publicEPV6 = net.JoinHostPort(publicIPV6, portStr)
		}
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
	encMyBundle, err := crypto.SealAAD(hybridKey, channelIDAad(channelID), myBundleBytes)
	if err != nil {
		return fmt.Errorf("encrypt endpoint bundle: %w", err)
	}
	logDebug("endpoint bundle encrypted, sending blob 4 (enc bundle) to sender via relay")
	if err := sig.SendBlob(channelID, encMyBundle); err != nil {
		return fmt.Errorf("send endpoint bundle blob 4: %w", err)
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
	punchResult, err := network.HolePunchDual(ctx, probeCtx, mux, candidatesV4, candidatesV6, holePunchNonce(hybridKey))
	if err != nil {
		return fmt.Errorf("hole punch: %w", err)
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
	computedHash, bytesReceived, tmpFile, destFile, err := receivePayload(ctx, meta, payloadStream, destination, isatty.IsTerminal(os.Stdout.Fd()))
	if err != nil {
		if peerErr := cancelledByPeer(err); peerErr != nil {
			if !quietMode {
				fmt.Fprint(os.Stderr, "\n")
			}
			return peerErr
		}
		if ctx.Err() != nil {
			if !quietMode {
				fmt.Fprint(os.Stderr, "\n")
			}
			return fmt.Errorf("You cancelled the transfer.")
		}
		return err
	}

	// removeSavedFile removes the temp file if one was saved.
	removeSavedFile := func() {
		if tmpFile != "" {
			os.Remove(tmpFile)
		}
	}

	// Verify received byte count against metadata when size is known.
	if meta.Size >= 0 && bytesReceived != meta.Size {
		removeSavedFile()
		logError("Received byte count mismatch",
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
		logError("Integrity check failed — sender hash does not match received data",
			"sender_sha256", senderHash, "computed_sha256", computedHash)
		fmt.Fprintf(os.Stderr, "Verification failed: received data does not match sender hash.\n")
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

	logInfo("Transfer complete", "kind", meta.Kind, "size_bytes", meta.Size, "bytes_received", bytesReceived)
	printStatus("Receive and verification complete.")
	return nil
}

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
		destPath = transfer.SafeDestinationPath(destination, name)
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

// readLenPrefixed reads a 4-byte big-endian length-prefixed message from r
// with a maximum allowed size of 1 MiB.
func readLenPrefixed(r io.Reader) ([]byte, error) {
	return readLenPrefixedMax(r, 1<<20)
}

// readLenPrefixedMax is like readLenPrefixed but with an explicit max byte limit.
func readLenPrefixedMax(r io.Reader, max uint32) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > max {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, max)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return buf, nil
}

// silence unused import for bufio — used in tx.go.
var _ = bufio.NewReader
