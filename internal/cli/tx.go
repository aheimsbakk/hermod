// Package cli: tx (send) command.
package cli

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/quic-go/quic-go"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/crypto"
	"github.com/hermod/hermod/internal/network"
	"github.com/hermod/hermod/pkg/transfer"
)

// newHashBar returns a progress bar styled with '=' fill and '-' padding.
// Used for transfers with a known size. Stream transfers use streamBar instead.
func newHashBar(size int64, description string) *progressbar.ProgressBar {
	return progressbar.NewOptions64(
		size,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowTotalBytes(true),
		progressbar.OptionSetWidth(10),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() { fmt.Fprint(os.Stderr, "\n") }),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerPadding: "-",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
}

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

	if saveServer && serverURL != cfg.ServerURL {
		config.SetDefaultServer(cfg, serverURL)
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("save configuration: %w", err)
		}
		printStatus("Default server set to %s", serverURL)
		logInfo("Default server updated", "server", serverURL)
	}

	// Determine payload kind
	isStdinPiped := !isatty.IsTerminal(os.Stdin.Fd())
	kind, name, err := transfer.ClassifyInput(input, isStdinPiped)
	if err != nil {
		return fmt.Errorf("classify input: %w", err)
	}
	logDebug("payload classified", "kind", kind, "name", name, "input", input)

	// Generate transfer code
	channelID, code, err := crypto.GenerateTransferCode(numWords)
	if err != nil {
		return fmt.Errorf("generate transfer code: %w", err)
	}
	password := strings.SplitN(code, "-", 2)[1]
	password = strings.ReplaceAll(password, "-", "-")
	logDebug("transfer code generated", "channel_id", channelID, "words", numWords)

	fmt.Fprintf(os.Stderr, "Transfer code: %s\n", code)

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

	// Allocate channel
	logDebug("allocating channel on signaling server", "channel_id", channelID)
	publicIPV4, publicIPV6, err := sig.Allocate(channelID)
	if err != nil {
		return fmt.Errorf("allocate channel: %w", err)
	}
	logInfo("Channel allocated", "channel_id", channelID, "public_ipv4", publicIPV4, "public_ipv6", publicIPV6)

	// Generate ephemeral TLS cert
	logDebug("generating ephemeral TLS certificate for QUIC")
	epCert, epKey, epCertDER, err := generateEphemeralCert()
	if err != nil {
		return fmt.Errorf("generate ephemeral certificate: %w", err)
	}
	myFP := network.CertFingerprint(epCertDER)
	logDebug("ephemeral certificate generated", "fingerprint", myFP)

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

	// CPace init
	logDebug("initialising CPace PAKE handshake", "role", "sender")
	cpaceSession, myPubMsg, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		return fmt.Errorf("initialize CPace handshake: %w", err)
	}

	// Wait for receiver to join
	logInfo("Waiting for receiver to join the channel")
	if err := sig.WaitReady(); err != nil {
		return fmt.Errorf("wait for receiver: %w", err)
	}
	logInfo("Receiver joined the channel")

	// Exchange CPace messages via relay
	logDebug("sending CPace public message to peer via relay")
	cpaceMsgBytes, err := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	if err != nil {
		return fmt.Errorf("encode CPace message: %w", err)
	}
	if err := sig.SendBlob(channelID, cpaceMsgBytes); err != nil {
		return fmt.Errorf("send CPace message: %w", err)
	}

	logDebug("waiting for peer CPace public message from relay")
	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("receive CPace message from peer: %w", err)
	}
	peerCPaceMsg, err := network.DecodeCPaceMsg(peerCPaceMsgBytes)
	if err != nil {
		return fmt.Errorf("decode peer CPace message: %w", err)
	}
	logDebug("peer CPace message received and decoded")

	// Finish CPace to get shared secret
	logDebug("completing CPace handshake to derive shared key")
	kClassical, err := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)
	if err != nil {
		return fmt.Errorf("complete CPace handshake: %w", err)
	}
	logInfo("PAKE handshake complete — shared key established")

	// Build local endpoints, split by address family
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

	bundle := network.EndpointBundle{
		LocalEndpointsV4: localV4,
		LocalEndpointsV6: localV6,
		PublicEndpointV4: publicEPV4,
		PublicEndpointV6: publicEPV6,
		CertFingerprint:  myFP,
		RequireVerify:    verify,
	}
	bundleBytes, err := network.EncodeEndpointBundle(bundle)
	if err != nil {
		return fmt.Errorf("encode endpoint bundle: %w", err)
	}
	encBundle, err := crypto.SealAAD(kClassical, channelIDAad(channelID), bundleBytes)
	if err != nil {
		return fmt.Errorf("encrypt endpoint bundle: %w", err)
	}
	logDebug("endpoint bundle encrypted and sending to peer via relay")
	if err := sig.SendBlob(channelID, encBundle); err != nil {
		return fmt.Errorf("send endpoint bundle: %w", err)
	}

	// Receive peer's bundle
	logDebug("waiting for receiver endpoint bundle from relay")
	encPeerBundle, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("receive endpoint bundle from peer: %w", err)
	}
	peerBundleBytes, err := crypto.OpenAAD(kClassical, channelIDAad(channelID), encPeerBundle)
	if err != nil {
		return fmt.Errorf("decrypt peer endpoint bundle: %w", err)
	}
	peerBundle, err := network.DecodeEndpointBundle(peerBundleBytes)
	if err != nil {
		return fmt.Errorf("decode peer endpoint bundle: %w", err)
	}
	logDebug("receiver endpoint bundle received",
		"public_v4", peerBundle.PublicEndpointV4,
		"public_v6", peerBundle.PublicEndpointV6,
		"local_v4_count", len(peerBundle.LocalEndpointsV4),
		"local_v6_count", len(peerBundle.LocalEndpointsV6),
		"require_verify", peerBundle.RequireVerify,
	)

	// Enforce verification symmetrically: if either side requires it, both must do it.
	if !verify && peerBundle.RequireVerify {
		logInfo("Receiver requested SAS verification — enabling for this transfer")
	}
	verify = verify || peerBundle.RequireVerify

	// Build candidate lists, split by address family.
	candidatesV4, err := network.ParseCandidates(peerBundle.CandidatesV4())
	if err != nil {
		return fmt.Errorf("parse IPv4 candidates: %w", err)
	}
	candidatesV6, err := network.ParseCandidates(peerBundle.CandidatesV6())
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

	// UDP hole punching — two-phase: IPv6 preferred, IPv4 fallback.
	logInfo("Starting UDP hole punch", "v4_candidates", len(candidatesV4), "v6_candidates", len(candidatesV6))
	printStatus("Establishing P2P connection...")
	punchResult, err := network.HolePunchDual(ctx, probeCtx, mux, candidatesV4, candidatesV6, holePunchNonce(kClassical))
	if err != nil {
		return fmt.Errorf("UDP hole punch: %w", err)
	}
	logInfo("UDP hole punch succeeded", "peer_addr", punchResult.PeerAddr.String())

	// QUIC dial (sender = QUIC client)
	logDebug("dialling QUIC connection to peer", "peer_addr", punchResult.PeerAddr.String())
	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{{
		Certificate: [][]byte{epCertDER},
		PrivateKey:  epKey,
		Leaf:        epCert,
	}}
	quicConn, err := network.DialQUIC(ctx, mux, punchResult.PeerAddr, tlsCfg, peerBundle.CertFingerprint)
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
		logInfo("SAS verification passed")
	}

	// Build metadata
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

	// Stream payload while computing SHA-256 in parallel via TeeReader (M-07).
	logInfo("Sending payload", "kind", meta.Kind, "size_bytes", meta.Size)
	isTTY := isatty.IsTerminal(os.Stderr.Fd())
	var payloadHash string
	if isTTY && !quietMode && size > 0 {
		bar := newHashBar(size, "sending")
		dest := io.MultiWriter(payloadStream, bar)
		payloadHash, err = transfer.HashStream(reader, dest)
	} else if isTTY && !quietMode && size < 0 {
		// Unknown size (stream): bouncing "###" bar that resizes with the terminal.
		bar := newStreamBar()
		dest := io.MultiWriter(payloadStream, bar)
		payloadHash, err = transfer.HashStream(reader, dest)
		bar.Finish()
	} else {
		payloadHash, err = transfer.HashStream(reader, payloadStream)
	}
	if err != nil {
		if peerErr := cancelledByPeer(err); peerErr != nil {
			if !quietMode {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by receiver.\n")
			}
			return peerErr
		}
		if ctx.Err() != nil {
			if !quietMode {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by sender.\n")
			}
			return fmt.Errorf("transfer cancelled")
		}
		return fmt.Errorf("send payload: %w", err)
	}
	payloadStream.Close()
	logDebug("payload stream closed — all bytes sent", "sha256", payloadHash)

	// Send trailing hash stream (stream 2). The receiver verifies the hash of
	// the received data against this value after draining the payload (M-07).
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
			if !quietMode {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by receiver.\n")
			}
			return peerErr
		}
		logWarn("did not receive acknowledgement from receiver — transfer may still have succeeded", "err", err)
	}

	logInfo("Transfer complete", "kind", meta.Kind, "size_bytes", meta.Size)
	printStatus("Transfer complete.")
	return nil
}

// buildPayload returns metadata and an io.Reader for the payload.
// SHA256 is always empty — the hash is computed during streaming and sent as
// trailing metadata (M-07). This avoids buffering large stdin inputs.
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
		// SHA256 intentionally empty — computed during streaming (M-07).
		meta := &transfer.Metadata{Kind: transfer.KindFile, Name: name, Size: size}
		return meta, f, size, nil

	case transfer.KindText:
		data := []byte(input)
		// SHA256 intentionally empty — computed during streaming (M-07).
		meta := &transfer.Metadata{Kind: transfer.KindText, Size: int64(len(data))}
		return meta, strings.NewReader(input), int64(len(data)), nil

	case transfer.KindStream:
		// Do not buffer stdin. Stream directly from os.Stdin while computing
		// hash in parallel via TeeReader in the send loop (M-07).
		// Size -1 signals unknown length to the progress bar logic.
		meta := &transfer.Metadata{Kind: transfer.KindStream, Size: -1}
		return meta, os.Stdin, -1, nil
	}
	return nil, nil, 0, fmt.Errorf("unknown payload kind: %s", kind)
}

// channelIDAad returns the 2-byte big-endian encoding of id for use as
// Additional Authenticated Data in AES-GCM endpoint bundle encryption (M-02).
func channelIDAad(id uint16) []byte {
	aad := make([]byte, 2)
	binary.BigEndian.PutUint16(aad, id)
	return aad
}

// holePunchNonce derives a 32-byte session-unique hash from the CPace shared
// key for use as hole-punch probe and ack discriminators.
// The caller uses hash[0:7] for the probe payload and hash[8:15] for the ack
// payload, giving 64 bits of entropy per packet — practically unguessable
// by an off-path attacker.
func holePunchNonce(kClassical []byte) [32]byte {
	return sha256.Sum256(append(kClassical, []byte("hermod-holepunch-v1")...))
}

// appendLenPrefix prepends a 4-byte big-endian length to data.
func appendLenPrefix(data []byte) []byte {
	out := make([]byte, 4+len(data))
	out[0] = byte(len(data) >> 24)
	out[1] = byte(len(data) >> 16)
	out[2] = byte(len(data) >> 8)
	out[3] = byte(len(data))
	copy(out[4:], data)
	return out
}

// generateEphemeralCert generates a short-lived self-signed X.509 cert and key.
// Uses ECDSA P-256 for fast key generation and smaller signatures (L-02).
// Returns the *x509.Certificate, crypto.PrivateKey, DER bytes, and error.
func generateEphemeralCert() (*x509.Certificate, interface{}, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "hermod-ephemeral"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, certDER, nil
}

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
var errSASCancelledByPeer = errors.New("the other side cancelled SAS verification")

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
		return "SAS verification cancelled by the other side"
	}
	return "SAS verification cancelled by user"
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
			msg := cancelMessage(ctx)
			if errors.Is(context.Cause(ctx), errSASCancelledByPeer) {
				fmt.Fprintln(os.Stderr, msg)
			} else {
				fmt.Fprintln(os.Stderr, msg+", notifying peer...")
			}
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
			return fmt.Errorf("Could not complete SAS verification: %w", err)
		}
	} else {
		stream, err = conn.AcceptStream(ctx)
		if err != nil {
			if cancelled {
				return errors.New(cancelMessage(ctx))
			}
			return fmt.Errorf("Could not complete SAS verification: %w", err)
		}
	}
	defer stream.Close()

	// Both sides write their result first, then read the peer's result.
	// This avoids deadlock on a bidirectional stream.
	if _, err := stream.Write([]byte{localByte}); err != nil {
		if cancelled {
			return errors.New(cancelMessage(ctx))
		}
		return fmt.Errorf("Could not send SAS result to the other side: %w", err)
	}

	var peerBuf [1]byte
	if _, err := io.ReadFull(stream, peerBuf[:]); err != nil {
		if cancelled {
			return errors.New(cancelMessage(ctx))
		}
		return fmt.Errorf("Could not read SAS result from the other side: %w", err)
	}

	switch {
	case cancelled && peerBuf[0] != 0x01:
		return errors.New(cancelMessage(ctx))
	case cancelled:
		return errors.New(cancelMessage(ctx))
	case !localOK && peerBuf[0] != 0x01:
		return fmt.Errorf("SAS verification rejected by both sides — connection aborted")
	case !localOK:
		return fmt.Errorf("SAS verification rejected by you — connection aborted")
	case peerBuf[0] != 0x01:
		return fmt.Errorf("SAS verification rejected by the other side — connection aborted")
	}
	return nil
}

// promptSASVerification shows the SAS + identicon and returns true if the user confirms.
// It reads user input from /dev/tty to avoid interference from piped stdin.
func promptSASVerification(ctx context.Context, tlsState tls.ConnectionState, sasContext []byte) (bool, error) {
	tty, err := openTTYFunc()
	if err != nil {
		return false, fmt.Errorf("open tty for SAS prompt: %w", err)
	}
	defer tty.Close()
	return promptSASVerificationFrom(ctx, tlsState, tty, sasContext)
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
	fmt.Fprintf(os.Stderr, "SAS: %s\n", crypto.SASString(words))
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

// quicConnectionState is satisfied by *quic.Conn.
type quicConnectionState interface {
	ConnectionState() tls.ConnectionState
}

func buildTLSCert(certDER []byte, key interface{}, leaf *x509.Certificate) tls.Certificate {
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// jsonPayload is used for text metadata exchange.
type jsonPayload = json.RawMessage
