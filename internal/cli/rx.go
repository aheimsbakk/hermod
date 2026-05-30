// Package cli: rx (receive) command.
package cli

import (
	"bufio"
	"context"
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
	"github.com/schollz/progressbar/v3"
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
		return fmt.Errorf("load config: %w", err)
	}

	if saveServer && serverURL != cfg.ServerURL {
		config.SetDefaultServer(cfg, serverURL)
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("save config: %w", err)
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
		return fmt.Errorf("ephemeral cert: %w", err)
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
	logInfo("Connecting to signaling server", "server", serverURL)
	sigRaw, err := network.DialSignaling(serverURL, pinnedFP)
	if err != nil {
		return fmt.Errorf("signaling connect: %w", err)
	}
	defer sigRaw.Close()
	sig := sigRaw.WithContext(ctx)
	logDebug("WebSocket connection to signaling server established")

	// Join channel
	logDebug("joining channel on signaling server", "channel_id", channelID)
	publicIP, err := sig.Join(channelID)
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	logInfo("Joined channel", "channel_id", channelID, "public_ip", publicIP)

	// Bind UDP socket
	logDebug("binding UDP socket", "addr", listenUDP)
	udpConn, err := network.BindUDP(listenUDP)
	if err != nil {
		return fmt.Errorf("bind udp: %w", err)
	}
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()

	localAddr, err := network.LocalUDPAddr(udpConn)
	if err != nil {
		return fmt.Errorf("local udp addr: %w", err)
	}
	logDebug("UDP socket bound", "local_addr", localAddr.String())

	// CPace init (receiver role)
	logDebug("initialising CPace PAKE handshake", "role", "receiver")
	cpaceSession, myPubMsg, err := crypto.CPaceInit(password, channelID, "receiver")
	if err != nil {
		return fmt.Errorf("cpace init: %w", err)
	}

	// Exchange CPace messages
	logDebug("waiting for sender CPace public message from relay")
	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("recv peer cpace msg: %w", err)
	}
	peerCPaceMsg, err := network.DecodeCPaceMsg(peerCPaceMsgBytes)
	if err != nil {
		return fmt.Errorf("decode peer cpace msg: %w", err)
	}
	logDebug("sender CPace message received and decoded")

	logDebug("sending CPace public message to peer via relay")
	cpaceMsgBytes, err := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	if err != nil {
		return fmt.Errorf("encode cpace msg: %w", err)
	}
	if err := sig.SendBlob(channelID, cpaceMsgBytes); err != nil {
		return fmt.Errorf("send cpace msg: %w", err)
	}

	// Finish CPace
	logDebug("completing CPace handshake to derive shared key")
	kClassical, err := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)
	if err != nil {
		return fmt.Errorf("cpace finish: %w", err)
	}
	logInfo("PAKE handshake complete — shared key established")

	// Receive sender's bundle
	logDebug("waiting for sender endpoint bundle from relay")
	encSenderBundle, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("recv sender bundle: %w", err)
	}
	senderBundleBytes, err := crypto.Open(kClassical, encSenderBundle)
	if err != nil {
		return fmt.Errorf("decrypt sender bundle: %w", err)
	}
	senderBundle, err := network.DecodeEndpointBundle(senderBundleBytes)
	if err != nil {
		return fmt.Errorf("decode sender bundle: %w", err)
	}
	logDebug("sender endpoint bundle received",
		"public", senderBundle.PublicEndpoint,
		"local_count", len(senderBundle.LocalEndpoints),
		"require_verify", senderBundle.RequireVerify,
	)

	// Enforce verification symmetrically: if either side requires it, both must do it.
	if !verify && senderBundle.RequireVerify {
		logInfo("Sender requested SAS verification — enabling for this transfer")
	}
	verify = verify || senderBundle.RequireVerify

	// Send our bundle
	localEPs, err := network.LocalEndpoints(localAddr.Port)
	if err != nil {
		localEPs = []string{}
		logWarn("could not enumerate local network interfaces — using public endpoint only", "err", err)
	}
	publicEP := net.JoinHostPort(publicIP, fmt.Sprintf("%d", localAddr.Port))
	logDebug("local endpoints collected", "local", localEPs, "public", publicEP)

	myBundle := network.EndpointBundle{
		LocalEndpoints:  localEPs,
		PublicEndpoint:  publicEP,
		CertFingerprint: myFP,
		RequireVerify:   verify,
	}
	myBundleBytes, err := network.EncodeEndpointBundle(myBundle)
	if err != nil {
		return fmt.Errorf("encode bundle: %w", err)
	}
	encMyBundle, err := crypto.Seal(kClassical, myBundleBytes)
	if err != nil {
		return fmt.Errorf("encrypt bundle: %w", err)
	}
	logDebug("endpoint bundle encrypted and sending to sender via relay")
	if err := sig.SendBlob(channelID, encMyBundle); err != nil {
		return fmt.Errorf("send bundle: %w", err)
	}

	// UDP hole punching
	allCandidates := []string{senderBundle.PublicEndpoint}
	allCandidates = append(allCandidates, senderBundle.LocalEndpoints...)
	candidates, err := network.ParseCandidates(allCandidates)
	if err != nil {
		return fmt.Errorf("parse candidates: %w", err)
	}
	logDebug("NAT candidates parsed", "count", len(candidates))

	logInfo("Starting UDP hole punch", "candidates", len(candidates))
	printStatus("Establishing P2P connection...")
	punchResult, err := network.HolePunch(ctx, mux, candidates)
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
		return fmt.Errorf("quic listen: %w", err)
	}
	defer ln.Close()

	// Trigger sender to dial by sending one more probe
	_ = punchResult // already punched

	logDebug("waiting for sender to establish QUIC connection")
	quicConn, err := ln.Accept(ctx)
	if err != nil {
		return fmt.Errorf("quic accept: %w", err)
	}
	defer quicConn.CloseWithError(0, "done")
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
		if err := performSASCoordinated(ctx, quicConn, quicState.TLS, false); err != nil {
			return err
		}
		logInfo("SAS verification passed")
	}

	// Read metadata stream
	logDebug("waiting for metadata stream from sender (stream 0)")
	metaStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept meta stream: %w", err)
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
	if err := receivePayload(ctx, meta, payloadStream, destination, isatty.IsTerminal(os.Stdout.Fd())); err != nil {
		if peerErr := cancelledByPeer(err); peerErr != nil {
			fmt.Fprintf(os.Stderr, "\nTransfer cancelled by sender.\n")
			return peerErr
		}
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "\nTransfer cancelled by receiver.\n")
			return fmt.Errorf("transfer cancelled")
		}
		return err
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
	return nil
}

// receivePayload routes the incoming stream according to meta.Kind and destination.
// stdoutIsTTY must be true when os.Stdout is a real terminal; callers should pass
// isatty.IsTerminal(os.Stdout.Fd()) so the function remains testable without a TTY.
func receivePayload(ctx context.Context, meta *transfer.Metadata, r io.Reader, destination string, stdoutIsTTY bool) error {
	isStdoutTTY := stdoutIsTTY

	switch {
	case destination != "":
		// Always save to disk
		return saveToFile(ctx, r, meta, destination)

	case !isStdoutTTY:
		// stdout is piped — stream bytes directly
		_, err := io.Copy(os.Stdout, r)
		return err

	default:
		// Interactive terminal
		switch meta.Kind {
		case transfer.KindText, transfer.KindStream:
			// Print to stdout; show progress bar on stderr when size is known.
			var src io.Reader = r
			if meta.Size > 0 {
				bar := progressbar.DefaultBytes(meta.Size, "receiving")
				src = io.TeeReader(r, bar)
			}
			_, err := io.Copy(os.Stdout, src)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr)
			logDebug("text payload written to stdout", "size_bytes", meta.Size)
			return nil

		case transfer.KindFile:
			// Save to current directory using original filename
			return saveToFile(ctx, r, meta, ".")
		}
	}
	return nil
}

// saveToFile writes incoming payload to a temp file, verifies SHA-256, then renames.
// If ctx is cancelled mid-transfer, the temp file is removed and an error is returned.
func saveToFile(ctx context.Context, r io.Reader, meta *transfer.Metadata, destination string) error {
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
		return fmt.Errorf("create temp file: %w", err)
	}

	// Ensure temp file is cleaned up on any error (including cancellation).
	var copyErr error
	defer func() {
		if copyErr != nil {
			f.Close()
			os.Remove(tmpPath)
		}
	}()

	isTTY := isatty.IsTerminal(os.Stderr.Fd())
	var w io.Writer = f
	if isTTY && meta.Size > 0 {
		bar := progressbar.DefaultBytes(meta.Size, "receiving")
		w = io.MultiWriter(f, bar)
	}

	if copyErr = transfer.VerifyStream(r, w, meta.SHA256); copyErr != nil {
		// Distinguish cancellation from integrity failure.
		if ctx.Err() != nil || cancelledByPeer(copyErr) != nil {
			logDebug("transfer interrupted — temp file removed", "path", tmpPath)
			return copyErr
		}
		logError("Integrity check failed — file removed", "path", tmpPath, "err", copyErr)
		return fmt.Errorf("integrity check failed: %w", copyErr)
	}

	if err := f.Close(); err != nil {
		copyErr = err
		return fmt.Errorf("close temp file: %w", err)
	}
	logDebug("integrity check passed", "sha256", meta.SHA256)

	if err := os.Rename(tmpPath, destPath); err != nil {
		copyErr = err
		return fmt.Errorf("finalize file: %w", err)
	}

	logInfo("File saved", "path", destPath, "size_bytes", meta.Size)
	printStatus("\nSaved to %s", destPath)
	return nil
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
