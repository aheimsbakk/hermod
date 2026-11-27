// Package cli: rx (receive) command.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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

	if err := saveDefaultServerIfSet(cfg, serverURL, saveServer); err != nil {
		return err
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
	myFP := network.PubKeyFingerprint(epCertDER)
	logDebug("ephemeral certificate generated", "fingerprint", myFP)

	// Enforce server trust — abort before any network call if the server
	// certificate has not been pinned via 'hermod trust'.
	logDebug("checking pinned fingerprint for server", "server", serverURL)
	pinnedFP, err := requireTrustedServer(cfg, serverURL)
	if err != nil {
		return err
	}

	// Connect to signaling server
	sigFamily := selectIPFamily()
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

	// Bind UDP socket and discover the external address on the raw conn.
	udpConn, localAddr, discoveredAddr, err := bindUDPAndDiscover(ctx, listenUDP, serverURL)
	if err != nil {
		return err
	}
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()

	ipFamily := selectIPFamily()

	// Hybrid key exchange and encrypted endpoint bundle exchange via the relay.
	senderBundle, hybridKey, verify, err := receiverHandshake(handshakeInput{
		sig:            sig,
		sigRaw:         sigRaw,
		password:       password,
		channelID:      channelID,
		verify:         verify,
		myFingerprint:  myFP,
		localAddr:      localAddr,
		discoveredAddr: discoveredAddr,
		publicIPV4:     publicIPV4,
		publicIPV6:     publicIPV6,
		ipFamily:       ipFamily,
	})
	if err != nil {
		return err
	}

	// Build candidate lists from sender's bundle, split by address family.
	candidatesV4, candidatesV6, err := parsePeerCandidates(&senderBundle, ipFamily)
	if err != nil {
		return err
	}

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
	ln, err := network.ListenQUIC(mux, tlsCert, baseTLS, senderBundle.PubKeyFingerprint)
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
	// Determine whether the last output line is already terminated. The
	// progress bar (hash bar) uses \r without \n, so the cancel handler
	// must print a \n to terminate it. For no-bar transfers the last
	// output line already ends with \n and no further \n is needed.
	rxIsTTY := isatty.IsTerminal(os.Stderr.Fd())
	lineTerminated := true
	if rxIsTTY && !quietMode && meta.Size > 0 {
		lineTerminated = false // saveToFile renders a \r-based hash bar
	}
	computedHash, bytesReceived, tmpFile, destFile, err := receivePayload(ctx, meta, payloadStream, destination, isatty.IsTerminal(os.Stdout.Fd()))
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
		return err
	}
	lineTerminated = true // payload receive succeeded, bar completed

	if err := finalizeTransfer(ctx, quicConn, meta, computedHash, bytesReceived, tmpFile, destFile); err != nil {
		return err
	}

	logInfo("Transfer complete", "kind", meta.Kind, "size_bytes", meta.Size, "bytes_received", bytesReceived)
	printStatus("Transfer complete.")
	return nil
}
