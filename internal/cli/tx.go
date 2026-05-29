// Package cli: tx (send) command.
package cli

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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

	fmt.Printf("Transfer code: %s\n", code)

	// Connect to signaling server
	logInfo("Connecting to signaling server", "server", serverURL)
	logDebug("looking up pinned fingerprint for server", "server", serverURL)
	pinnedFP := cfg.TrustedServers[serverURL]
	sigRaw, err := network.DialSignaling(serverURL, pinnedFP)
	if err != nil {
		return fmt.Errorf("signaling connect: %w", err)
	}
	defer sigRaw.Close()
	sig := sigRaw.WithContext(ctx)
	logDebug("WebSocket connection to signaling server established")

	// Allocate channel
	logDebug("allocating channel on signaling server", "channel_id", channelID)
	publicIP, err := sig.Allocate(channelID)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}
	logInfo("Channel allocated", "channel_id", channelID, "public_ip", publicIP)

	// Generate ephemeral TLS cert
	logDebug("generating ephemeral TLS certificate for QUIC")
	epCert, epKey, epCertDER, err := generateEphemeralCert()
	if err != nil {
		return fmt.Errorf("ephemeral cert: %w", err)
	}
	myFP := network.CertFingerprint(epCertDER)
	logDebug("ephemeral certificate generated", "fingerprint", myFP)

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

	// CPace init
	logDebug("initialising CPace PAKE handshake", "role", "sender")
	cpaceSession, myPubMsg, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		return fmt.Errorf("cpace init: %w", err)
	}

	// Wait for receiver to join
	logInfo("Waiting for receiver to join the channel")
	if err := sig.WaitReady(); err != nil {
		return fmt.Errorf("wait ready: %w", err)
	}
	logInfo("Receiver joined the channel")

	// Exchange CPace messages via relay
	logDebug("sending CPace public message to peer via relay")
	cpaceMsgBytes, err := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	if err != nil {
		return fmt.Errorf("encode cpace msg: %w", err)
	}
	if err := sig.SendBlob(channelID, cpaceMsgBytes); err != nil {
		return fmt.Errorf("send cpace msg: %w", err)
	}

	logDebug("waiting for peer CPace public message from relay")
	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("recv peer cpace msg: %w", err)
	}
	peerCPaceMsg, err := network.DecodeCPaceMsg(peerCPaceMsgBytes)
	if err != nil {
		return fmt.Errorf("decode peer cpace msg: %w", err)
	}
	logDebug("peer CPace message received and decoded")

	// Finish CPace to get shared secret
	logDebug("completing CPace handshake to derive shared key")
	kClassical, err := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)
	if err != nil {
		return fmt.Errorf("cpace finish: %w", err)
	}
	logInfo("PAKE handshake complete — shared key established")

	// Build local endpoints
	localEPs, err := network.LocalEndpoints(localAddr.Port)
	if err != nil {
		localEPs = []string{}
		logWarn("could not enumerate local network interfaces — using public endpoint only", "err", err)
	}
	publicEP := net.JoinHostPort(publicIP, fmt.Sprintf("%d", localAddr.Port))
	logDebug("local endpoints collected", "local", localEPs, "public", publicEP)

	bundle := network.EndpointBundle{
		LocalEndpoints:  localEPs,
		PublicEndpoint:  publicEP,
		CertFingerprint: myFP,
		RequireVerify:   verify,
	}
	bundleBytes, err := network.EncodeEndpointBundle(bundle)
	if err != nil {
		return fmt.Errorf("encode bundle: %w", err)
	}
	encBundle, err := crypto.Seal(kClassical, bundleBytes)
	if err != nil {
		return fmt.Errorf("encrypt bundle: %w", err)
	}
	logDebug("endpoint bundle encrypted and sending to peer via relay")
	if err := sig.SendBlob(channelID, encBundle); err != nil {
		return fmt.Errorf("send bundle: %w", err)
	}

	// Receive peer's bundle
	logDebug("waiting for receiver endpoint bundle from relay")
	encPeerBundle, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("recv peer bundle: %w", err)
	}
	peerBundleBytes, err := crypto.Open(kClassical, encPeerBundle)
	if err != nil {
		return fmt.Errorf("decrypt peer bundle: %w", err)
	}
	peerBundle, err := network.DecodeEndpointBundle(peerBundleBytes)
	if err != nil {
		return fmt.Errorf("decode peer bundle: %w", err)
	}
	logDebug("receiver endpoint bundle received",
		"public", peerBundle.PublicEndpoint,
		"local_count", len(peerBundle.LocalEndpoints),
		"require_verify", peerBundle.RequireVerify,
	)

	// Enforce verification symmetrically: if either side requires it, both must do it.
	if !verify && peerBundle.RequireVerify {
		logInfo("Receiver requested SAS verification — enabling for this transfer")
	}
	verify = verify || peerBundle.RequireVerify

	// Build candidate list
	allCandidates := []string{peerBundle.PublicEndpoint}
	allCandidates = append(allCandidates, peerBundle.LocalEndpoints...)
	candidates, err := network.ParseCandidates(allCandidates)
	if err != nil {
		return fmt.Errorf("parse candidates: %w", err)
	}
	logDebug("NAT candidates parsed", "count", len(candidates))

	// UDP hole punching
	logInfo("Starting UDP hole punch", "candidates", len(candidates))
	printStatus("Establishing P2P connection...")
	punchResult, err := network.HolePunch(ctx, mux, candidates)
	if err != nil {
		return fmt.Errorf("hole punch: %w", err)
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
		return fmt.Errorf("quic dial: %w", err)
	}
	defer quicConn.CloseWithError(0, "done")
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
		if err := performSASCoordinated(ctx, quicConn, quicState.TLS, true); err != nil {
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
		return fmt.Errorf("open meta stream: %w", err)
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

	logInfo("Sending payload", "kind", meta.Kind, "size_bytes", meta.Size)
	isTTY := isatty.IsTerminal(os.Stderr.Fd())
	if isTTY && size > 0 {
		bar := progressbar.DefaultBytes(size, "sending")
		if _, err := io.Copy(io.MultiWriter(payloadStream, bar), reader); err != nil {
			if peerErr := cancelledByPeer(err); peerErr != nil {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by receiver.\n")
				return peerErr
			}
			if ctx.Err() != nil {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by sender.\n")
				return fmt.Errorf("transfer cancelled")
			}
			return fmt.Errorf("send payload: %w", err)
		}
	} else {
		if _, err := io.Copy(payloadStream, reader); err != nil {
			if peerErr := cancelledByPeer(err); peerErr != nil {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by receiver.\n")
				return peerErr
			}
			if ctx.Err() != nil {
				fmt.Fprintf(os.Stderr, "\nTransfer cancelled by sender.\n")
				return fmt.Errorf("transfer cancelled")
			}
			return fmt.Errorf("send payload: %w", err)
		}
	}
	payloadStream.Close()
	logDebug("payload stream closed — all bytes sent")

	// Wait for receiver to signal it has finished reading before closing the connection.
	// This prevents the QUIC connection from closing before rx accepts the streams.
	logDebug("waiting for receiver acknowledgement")
	ackStream, err := quicConn.AcceptStream(ctx)
	if err == nil {
		ackStream.Close()
		logDebug("acknowledgement received from receiver")
	} else {
		if peerErr := cancelledByPeer(err); peerErr != nil {
			fmt.Fprintf(os.Stderr, "\nTransfer cancelled by receiver.\n")
			return peerErr
		}
		logWarn("did not receive acknowledgement from receiver — transfer may still have succeeded", "err", err)
	}

	logInfo("Transfer complete", "kind", meta.Kind, "size_bytes", meta.Size)
	printStatus("Transfer complete.")
	return nil
}

// buildPayload returns metadata and an io.Reader for the payload.
func buildPayload(input string, kind transfer.Kind, name string, isStdinPiped bool) (*transfer.Metadata, io.Reader, int64, error) {
	switch kind {
	case transfer.KindFile:
		hash, size, err := transfer.HashFile(input)
		if err != nil {
			return nil, nil, 0, err
		}
		f, err := os.Open(input)
		if err != nil {
			return nil, nil, 0, err
		}
		meta := &transfer.Metadata{Kind: transfer.KindFile, Name: name, Size: size, SHA256: hash}
		return meta, f, size, nil

	case transfer.KindText:
		data := []byte(input)
		hash := transfer.HashBytes(data)
		meta := &transfer.Metadata{Kind: transfer.KindText, Size: int64(len(data)), SHA256: hash}
		return meta, strings.NewReader(input), int64(len(data)), nil

	case transfer.KindStream:
		// stdin — we buffer to compute hash (required for metadata)
		var buf []byte
		scanner := bufio.NewReader(os.Stdin)
		buf, err := io.ReadAll(scanner)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("read stdin: %w", err)
		}
		hash := transfer.HashBytes(buf)
		meta := &transfer.Metadata{Kind: transfer.KindStream, Size: int64(len(buf)), SHA256: hash}
		return meta, strings.NewReader(string(buf)), int64(len(buf)), nil
	}
	return nil, nil, 0, fmt.Errorf("unknown kind: %s", kind)
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
// Returns the *x509.Certificate, crypto.PrivateKey, DER bytes, and error.
func generateEphemeralCert() (*x509.Certificate, interface{}, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
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

// performSASCoordinated shows the SAS prompt, then exchanges a 1-byte
// confirmation with the peer over a dedicated QUIC stream. Both sides must
// confirm; if either rejects, the transfer is aborted.
//
// isSender=true: sender opens the SAS stream (QUIC client role).
// isSender=false: receiver accepts the SAS stream (QUIC server role).
//
// User input is read from /dev/tty so that piped stdin does not interfere.
func performSASCoordinated(ctx context.Context, conn *quic.Conn, tlsState tls.ConnectionState, isSender bool) error {
	tty, err := openTTYFunc()
	if err != nil {
		return fmt.Errorf("open tty for SAS prompt: %w", err)
	}
	defer tty.Close()
	return performSASCoordinatedWith(ctx, &quicSASConn{conn}, tlsState, isSender, tty)
}

// performSASCoordinatedWith is the injectable core used by tests.
func performSASCoordinatedWith(ctx context.Context, conn sasStreamConn, tlsState tls.ConnectionState, isSender bool, reader io.Reader) error {
	// Show prompt and collect local answer first.
	localOK, err := promptSASVerificationFrom(tlsState, reader)
	if err != nil {
		return err
	}

	var localByte byte
	if localOK {
		localByte = 0x01
	}

	var stream io.ReadWriteCloser
	if isSender {
		stream, err = conn.OpenStreamSync(ctx)
		if err != nil {
			return fmt.Errorf("open sas stream: %w", err)
		}
	} else {
		stream, err = conn.AcceptStream(ctx)
		if err != nil {
			return fmt.Errorf("accept sas stream: %w", err)
		}
	}
	defer stream.Close()

	// Both sides write their result first, then read the peer's result.
	// This avoids deadlock on a bidirectional stream.
	if _, err := stream.Write([]byte{localByte}); err != nil {
		return fmt.Errorf("send sas result: %w", err)
	}

	var peerBuf [1]byte
	if _, err := io.ReadFull(stream, peerBuf[:]); err != nil {
		return fmt.Errorf("recv peer sas result: %w", err)
	}

	if !localOK && peerBuf[0] != 0x01 {
		return fmt.Errorf("SAS verification rejected by both sides — connection aborted")
	}
	if !localOK {
		return fmt.Errorf("SAS verification rejected by %s — connection aborted", map[bool]string{true: "sender", false: "receiver"}[isSender])
	}
	if peerBuf[0] != 0x01 {
		return fmt.Errorf("SAS verification rejected by %s — connection aborted", map[bool]string{true: "receiver", false: "sender"}[isSender])
	}
	return nil
}

// promptSASVerification shows the SAS + identicon and returns true if the user confirms.
// It reads user input from /dev/tty to avoid interference from piped stdin.
func promptSASVerification(tlsState tls.ConnectionState) (bool, error) {
	tty, err := openTTYFunc()
	if err != nil {
		return false, fmt.Errorf("open tty for SAS prompt: %w", err)
	}
	defer tty.Close()
	return promptSASVerificationFrom(tlsState, tty)
}

// promptSASVerificationFrom shows the SAS + identicon and reads the answer from r.
// Separating the reader makes this testable without a real terminal.
func promptSASVerificationFrom(tlsState tls.ConnectionState, r io.Reader) (bool, error) {
	material, err := tlsState.ExportKeyingMaterial("hermod-sas-v1", nil, 32)
	if err != nil {
		return false, fmt.Errorf("export keying material: %w", err)
	}

	words := crypto.SASFromBytes(material)
	fmt.Fprintf(os.Stderr, "=== Out-of-Band Verification ===\n")
	fmt.Fprintf(os.Stderr, "SAS: %s\n", crypto.SASString(words))
	fmt.Fprintln(os.Stderr, crypto.Identicon(material[:16]))
	fmt.Fprint(os.Stderr, "Compare these values with the other end. Do they match? [y/N]: ")

	scanner := bufio.NewScanner(r)
	var answer string
	if scanner.Scan() {
		answer = strings.TrimSpace(scanner.Text())
	}
	return answer == "y" || answer == "Y", nil
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
