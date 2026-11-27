// Package cli: tx (send) command.
package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
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

func newTxCmd() *cobra.Command {
	var (
		serverURL string
		numWords  int
		verify    bool
		listenUDP string
	)

	cmd := &cobra.Command{
		Use:     "tx [INPUT]",
		Aliases: []string{"send"},
		Short:   "Send a file, text, or stdin stream",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := ""
			if len(args) > 0 {
				input = args[0]
			}
			return runTx(input, serverURL, numWords, verify, listenUDP, cmd.Flags().Changed("server"))
		},
	}

	cmd.Flags().StringVarP(&serverURL, "server", "s", configServerURL(), "Signaling server URL")
	cmd.Flags().IntVarP(&numWords, "words", "w", 3, "Number of words in transfer code")
	cmd.Flags().BoolVarP(&verify, "verify", "v", false, "Enforce SAS out-of-band verification")
	cmd.Flags().StringVarP(&listenUDP, "listen", "l", envOrDefault("HERMOD_LISTEN", ":0"), "Local UDP bind address")

	return cmd
}

func runTx(input, serverURL string, numWords int, verify bool, listenUDP string, saveServer bool) error {
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

	// Determine payload kind
	isStdinPiped := !isatty.IsTerminal(os.Stdin.Fd())
	kind, name, err := transfer.ClassifyInput(input, isStdinPiped)
	if err != nil {
		return fmt.Errorf("classify input: %w", err)
	}
	loggedInput := input
	if kind == transfer.KindText {
		loggedInput = "<redacted>"
	}
	logDebug("payload classified", "kind", kind, "name", name, "input", loggedInput)

	// Generate transfer code
	channelID, code, err := crypto.GenerateTransferCode(numWords)
	if err != nil {
		return fmt.Errorf("generate transfer code: %w", err)
	}
	password := strings.SplitN(code, "-", 2)[1]
	password = strings.ReplaceAll(password, "-", "-")
	logDebug("transfer code generated", "channel_id", channelID, "words", numWords)

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

	// Allocate channel
	logDebug("allocating channel on signaling server", "channel_id", channelID)
	publicIPV4, publicIPV6, err := sig.Allocate(channelID)
	if err != nil {
		return fmt.Errorf("allocate channel: %w", err)
	}
	logInfo("Channel allocated", "channel_id", channelID, "public_ipv4", publicIPV4, "public_ipv6", publicIPV6)

	// Print transfer code after the channel has been allocated on the server.
	// If printed earlier, a receiver who reads the code and joins immediately
	// may beat the Allocate call, causing a "channel does not exist" rejection.
	fmt.Fprintf(os.Stderr, "Transfer code: %s\n", code)

	// Generate ephemeral TLS cert
	logDebug("generating ephemeral TLS certificate for QUIC")
	epCert, epKey, epCertDER, err := generateEphemeralCert()
	if err != nil {
		return fmt.Errorf("generate ephemeral certificate: %w", err)
	}
	myFP := network.PubKeyFingerprint(epCertDER)
	logDebug("ephemeral certificate generated", "fingerprint", myFP)

	// Bind UDP socket and discover the external address on the raw conn.
	udpConn, localAddr, discoveredAddr, err := bindUDPAndDiscover(ctx, listenUDP, serverURL)
	if err != nil {
		return err
	}
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()

	ipFamily := selectIPFamily()

	// Hybrid key exchange and encrypted endpoint bundle exchange via the relay.
	peerBundle, hybridKey, verify, err := senderHandshake(handshakeInput{
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

	// Build candidate lists, split by address family.
	candidatesV4, candidatesV6, err := parsePeerCandidates(&peerBundle, ipFamily)
	if err != nil {
		return err
	}

	// Create a probe context that outlives HolePunch so probing continues
	// until the QUIC connection is established, preventing NAT mappings from
	// expiring in the gap between hole-punch return and QUIC handshake.
	probeCtx, probeCancel := context.WithCancel(ctx)
	defer probeCancel()

	// UDP hole punching — two-phase: IPv6 preferred, IPv4 fallback.
	logInfo("Starting UDP hole punch", "v4_candidates", len(candidatesV4), "v6_candidates", len(candidatesV6))
	printStatus("Establishing P2P connection...")
	punchResult, err := network.HolePunchDual(ctx, probeCtx, mux, candidatesV4, candidatesV6, holePunchNonce(hybridKey))
	if err != nil {
		return fmt.Errorf("hole punch: %w", err)
	}
	logInfo("UDP hole punch succeeded", "peer_addr", punchResult.PeerAddr.String())

	// QUIC dial (sender = QUIC client)
	logDebug("dialling QUIC connection to peer", "peer_addr", punchResult.PeerAddr.String())
	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{buildTLSCert(epCertDER, epKey, epCert)}
	quicConn, err := network.DialQUIC(ctx, mux, punchResult.PeerAddr, tlsCfg, peerBundle.PubKeyFingerprint)
	if err != nil {
		return fmt.Errorf("QUIC dial: %w", err)
	}
	defer quicConn.CloseWithError(0, "done")
	// Stop probing — QUIC keepalive will maintain the NAT mapping from now on.
	probeCancel()
	logInfo("QUIC connection established", "peer_addr", punchResult.PeerAddr.String())

	// Watch for Ctrl+C: close the connection so the receiver is notified immediately.
	go func() {
		<-ctx.Done()
		quicConn.CloseWithError(cancelCodeUser, cancelMsgSender)
	}()

	// SAS verification (optional)
	if verify {
		logInfo("Starting SAS out-of-band verification")
		quicState := quicConn.ConnectionState()
		if err := performSASCoordinated(ctx, quicConn, quicState.TLS, true, channelIDAad(channelID)); err != nil {
			return err
		}
	}

	// Build and send the payload over the coordinated QUIC streams.
	logDebug("reading and hashing payload", "kind", kind, "name", name)
	meta, reader, size, err := buildPayload(input, kind, name, isStdinPiped)
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}
	if reader != nil {
		defer func() {
			if closer, ok := reader.(io.Closer); ok {
				closer.Close()
			}
		}()
	}
	logDebug("payload ready", "kind", meta.Kind, "size_bytes", meta.Size, "sha256", meta.SHA256)

	if err := sendPayloadStreams(ctx, quicConn, meta, reader, size); err != nil {
		return err
	}

	logInfo("Transfer complete", "kind", meta.Kind, "size_bytes", meta.Size)
	printStatus("Transfer complete.")
	return nil
}
