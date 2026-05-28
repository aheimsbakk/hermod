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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-isatty"
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
			return runTx(input, serverURL, numWords, verify, listenUDP)
		},
	}

	cmd.Flags().StringVarP(&serverURL, "server", "s", envOrDefault("HERMOD_SERVER", "wss://localhost:4376"), "Signaling server URL")
	cmd.Flags().IntVarP(&numWords, "words", "w", 3, "Number of words in transfer code")
	cmd.Flags().BoolVarP(&verify, "verify", "v", false, "Enforce SAS out-of-band verification")
	cmd.Flags().StringVarP(&listenUDP, "listen", "l", envOrDefault("HERMOD_LISTEN", ":0"), "Local UDP bind address")

	return cmd
}

func runTx(input, serverURL string, numWords int, verify bool, listenUDP string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Determine payload kind
	isStdinPiped := !isatty.IsTerminal(os.Stdin.Fd())
	kind, name, err := transfer.ClassifyInput(input, isStdinPiped)
	if err != nil {
		return fmt.Errorf("classify input: %w", err)
	}

	// Generate transfer code
	channelID, code, err := crypto.GenerateTransferCode(numWords)
	if err != nil {
		return fmt.Errorf("generate transfer code: %w", err)
	}
	password := strings.SplitN(code, "-", 2)[1]
	password = strings.ReplaceAll(password, "-", "-")

	fmt.Printf("Transfer code: %s\n", code)

	// Connect to signaling server
	pinnedFP := cfg.TrustedServers[serverURL]
	sig, err := network.DialSignaling(serverURL, pinnedFP)
	if err != nil {
		return fmt.Errorf("signaling connect: %w", err)
	}
	defer sig.Close()

	// Allocate channel
	publicIP, err := sig.Allocate(channelID)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}

	// Generate ephemeral TLS cert
	epCert, epKey, epCertDER, err := generateEphemeralCert()
	if err != nil {
		return fmt.Errorf("ephemeral cert: %w", err)
	}
	myFP := network.CertFingerprint(epCertDER)

	// Bind UDP socket
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

	// CPace init
	cpaceSession, myPubMsg, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		return fmt.Errorf("cpace init: %w", err)
	}

	// Wait for receiver to join
	if err := sig.WaitReady(); err != nil {
		return fmt.Errorf("wait ready: %w", err)
	}

	// Exchange CPace messages via relay
	cpaceMsgBytes, err := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	if err != nil {
		return fmt.Errorf("encode cpace msg: %w", err)
	}
	if err := sig.SendBlob(channelID, cpaceMsgBytes); err != nil {
		return fmt.Errorf("send cpace msg: %w", err)
	}

	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("recv peer cpace msg: %w", err)
	}
	peerCPaceMsg, err := network.DecodeCPaceMsg(peerCPaceMsgBytes)
	if err != nil {
		return fmt.Errorf("decode peer cpace msg: %w", err)
	}

	// Finish CPace to get shared secret
	kClassical, err := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)
	if err != nil {
		return fmt.Errorf("cpace finish: %w", err)
	}

	// Build local endpoints
	localEPs, err := network.LocalEndpoints(localAddr.Port)
	if err != nil {
		localEPs = []string{}
	}
	publicEP := fmt.Sprintf("%s:%d", publicIP, localAddr.Port)

	bundle := network.EndpointBundle{
		LocalEndpoints:  localEPs,
		PublicEndpoint:  publicEP,
		CertFingerprint: myFP,
	}
	bundleBytes, err := network.EncodeEndpointBundle(bundle)
	if err != nil {
		return fmt.Errorf("encode bundle: %w", err)
	}
	encBundle, err := crypto.Seal(kClassical, bundleBytes)
	if err != nil {
		return fmt.Errorf("encrypt bundle: %w", err)
	}
	if err := sig.SendBlob(channelID, encBundle); err != nil {
		return fmt.Errorf("send bundle: %w", err)
	}

	// Receive peer's bundle
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

	// Build candidate list
	allCandidates := []string{peerBundle.PublicEndpoint}
	allCandidates = append(allCandidates, peerBundle.LocalEndpoints...)
	candidates, err := network.ParseCandidates(allCandidates)
	if err != nil {
		return fmt.Errorf("parse candidates: %w", err)
	}

	// UDP hole punching
	fmt.Fprintln(os.Stderr, "Establishing P2P connection...")
	punchResult, err := network.HolePunch(ctx, mux, candidates)
	if err != nil {
		return fmt.Errorf("hole punch: %w", err)
	}

	// QUIC dial (sender = QUIC client)
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

	// SAS verification (optional)
	if verify {
		quicState := quicConn.ConnectionState()
		if err := performSASVerification(quicState.TLS); err != nil {
			return err
		}
	}

	// Build metadata
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

	// Open metadata stream
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

	// Open payload stream
	payloadStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open payload stream: %w", err)
	}

	isTTY := isatty.IsTerminal(os.Stderr.Fd())
	if isTTY && size > 0 {
		bar := progressbar.DefaultBytes(size, "sending")
		if _, err := io.Copy(io.MultiWriter(payloadStream, bar), reader); err != nil {
			return fmt.Errorf("send payload: %w", err)
		}
	} else {
		if _, err := io.Copy(payloadStream, reader); err != nil {
			return fmt.Errorf("send payload: %w", err)
		}
	}
	payloadStream.Close()

	// Wait for receiver to signal it has finished reading before closing the connection.
	// This prevents the QUIC connection from closing before rx accepts the streams.
	ackStream, err := quicConn.AcceptStream(ctx)
	if err == nil {
		ackStream.Close()
	}

	fmt.Fprintln(os.Stderr, "Transfer complete.")
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

// performSASVerification extracts key material from the QUIC TLS connection and
// displays the SAS + identicon for user confirmation.
func performSASVerification(tlsState tls.ConnectionState) error {
	material, err := tlsState.ExportKeyingMaterial("hermod-sas-v1", nil, 32)
	if err != nil {
		return fmt.Errorf("export keying material: %w", err)
	}

	words := crypto.SASFromBytes(material)
	fmt.Printf("\n=== Out-of-Band Verification ===\n")
	fmt.Printf("SAS: %s\n\n", crypto.SASString(words))
	fmt.Println(crypto.Identicon(material[:16]))
	fmt.Println("Compare these values with the other end. Do they match? [y/N]: ")

	var answer string
	fmt.Scanln(&answer)
	if answer != "y" && answer != "Y" {
		return fmt.Errorf("SAS verification failed — connection aborted")
	}
	return nil
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
