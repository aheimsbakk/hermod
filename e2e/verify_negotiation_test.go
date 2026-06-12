// Package e2e: integration tests for symmetric -v (verify) negotiation.
//
// Rules under test:
//   - Sender requests verify  → receiver is forced to perform SAS verification
//   - Receiver requests verify → sender is forced to perform SAS verification
//   - Neither requests verify  → SAS verification is skipped on both sides
package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/crypto"
	"github.com/hermod/hermod/internal/network"
	"github.com/hermod/hermod/pkg/transfer"
)

// verifyResult is returned by runSenderVerify / runReceiverVerify.
type verifyResult struct {
	// sasTriggered is true when the peer's bundle had RequireVerify set
	// OR the local flag was set — i.e. the merged verify value was true.
	sasTriggered bool
	sasWords     []string // SAS words computed from TLS key material
	payload      []byte   // receiver only
	err          error
}

// runSenderVerify is like runSender but accepts requireVerify and reports
// whether SAS verification would have been triggered (merged flag).
// It does NOT actually perform the interactive SAS prompt — it only reads
// the merged flag value so tests remain non-interactive.
func runSenderVerify(serverURL string, channelID uint16, password string, payload []byte, requireVerify bool, allocReady chan<- struct{}) verifyResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := config.Default()

	epLeaf, epKey, epCertDER, err := generateTestEphemeralCert()
	if err != nil {
		return verifyResult{err: fmt.Errorf("gen cert: %w", err)}
	}
	myFP := network.CertFingerprint(epCertDER)

	sig, err := network.DialSignaling(context.Background(), serverURL, "")
	if err != nil {
		return verifyResult{err: fmt.Errorf("dial: %w", err)}
	}
	defer sig.Close()

	publicIPV4, publicIPV6, err := sig.Allocate(channelID)
	if err != nil {
		return verifyResult{err: fmt.Errorf("allocate: %w", err)}
	}
	// Signal that the channel is allocated so the receiver can safely join.
	close(allocReady)

	udpConn, err := network.BindUDP(":0")
	if err != nil {
		return verifyResult{err: fmt.Errorf("bind UDP socket: %w", err)}
	}
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()

	localAddr, _ := network.LocalUDPAddr(udpConn)

	cpaceSession, myPubMsg, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		return verifyResult{err: fmt.Errorf("initialize CPace handshake: %w", err)}
	}

	x25519Priv, x25519Pub, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return verifyResult{err: fmt.Errorf("generate X25519 key pair: %w", err)}
	}

	if err := sig.WaitReady(); err != nil {
		return verifyResult{err: fmt.Errorf("wait ready: %w", err)}
	}

	blob1 := network.SenderHandshakeBlob(myPubMsg, x25519Pub)
	sig.SendBlob(channelID, blob1)

	blob2, err := sig.RecvBlob()
	if err != nil {
		return verifyResult{err: fmt.Errorf("recv handshake blob: %w", err)}
	}
	peerCPacePub, peerX25519Pub, mlkemEncapKey, err := network.ParseReceiverHandshakeBlob(blob2)
	if err != nil {
		return verifyResult{err: fmt.Errorf("parse receiver handshake blob: %w", err)}
	}

	kClassical, err := cpaceSession.CPaceFinish(peerCPacePub)
	if err != nil {
		return verifyResult{err: fmt.Errorf("complete CPace handshake: %w", err)}
	}

	peerX25519Key, err := crypto.NewX25519PubFromBytes(peerX25519Pub)
	if err != nil {
		return verifyResult{err: fmt.Errorf("parse peer X25519 pub: %w", err)}
	}
	ssX25519, err := crypto.ECDHX25519(x25519Priv, peerX25519Key)
	if err != nil {
		return verifyResult{err: fmt.Errorf("compute X25519 shared secret: %w", err)}
	}

	peerMLKEMKey, err := crypto.NewEncapsulationKey768Bytes(mlkemEncapKey)
	if err != nil {
		return verifyResult{err: fmt.Errorf("parse peer ML-KEM key: %w", err)}
	}
	ssMLKEM, kemCt := crypto.EncapsulateMLKEM(peerMLKEMKey)

	hybridKey := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)

	localV4, localV6, _ := network.LocalEndpoints(localAddr.Port, network.IPFamilyAny)
	portStr := fmt.Sprintf("%d", localAddr.Port)
	var publicEPV4, publicEPV6 string
	if publicIPV4 != "" {
		publicEPV4 = net.JoinHostPort(publicIPV4, portStr)
	}
	if publicIPV6 != "" {
		publicEPV6 = net.JoinHostPort(publicIPV6, portStr)
	}
	bundle := network.EndpointBundle{
		LocalEndpointsV4: localV4,
		LocalEndpointsV6: localV6,
		PublicEndpointV4: publicEPV4,
		PublicEndpointV6: publicEPV6,
		CertFingerprint:  myFP,
		RequireVerify:    requireVerify,
	}
	bundleBytes, _ := network.EncodeEndpointBundle(bundle)
	encBundle, _ := crypto.SealAAD(hybridKey, channelIDAad(channelID), bundleBytes)

	blob3 := network.SenderBundleBlob(kemCt, encBundle)
	sig.SendBlob(channelID, blob3)

	encPeerBundle, err := sig.RecvBlob()
	if err != nil {
		return verifyResult{err: fmt.Errorf("receive endpoint bundle from peer: %w", err)}
	}
	peerBundleBytes, err := crypto.OpenAAD(hybridKey, channelIDAad(channelID), encPeerBundle)
	if err != nil {
		return verifyResult{err: fmt.Errorf("decrypt peer bundle: %w", err)}
	}
	peerBundle, err := network.DecodeEndpointBundle(peerBundleBytes)
	if err != nil {
		return verifyResult{err: fmt.Errorf("decode peer endpoint bundle: %w", err)}
	}

	// Symmetric merge — same logic as cli/tx.go.
	mergedVerify := requireVerify || peerBundle.RequireVerify

	candidatesV4, _ := network.ParseCandidates(peerBundle.CandidatesV4())
	candidatesV6, _ := network.ParseCandidates(peerBundle.CandidatesV6())
	punchResult, err := network.HolePunchDual(ctx, ctx, mux, candidatesV4, candidatesV6, [32]byte{})
	if err != nil {
		return verifyResult{err: fmt.Errorf("UDP hole punch: %w", err)}
	}

	time.Sleep(200 * time.Millisecond)

	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCert := buildTLSCertFromDER(epCertDER, epKey, epLeaf)
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	quicConn, err := network.DialQUIC(ctx, mux, punchResult.PeerAddr, tlsCfg, peerBundle.CertFingerprint)
	if err != nil {
		return verifyResult{err: fmt.Errorf("QUIC dial: %w", err)}
	}

	// Compute SAS from TLS key material for cross-check.
	sasCtx := make([]byte, 2)
	binary.BigEndian.PutUint16(sasCtx, channelID)
	quicState := quicConn.ConnectionState()
	material, err := quicState.TLS.ExportKeyingMaterial("hermod-sas-v1", sasCtx, 32)
	var sasWords []string
	if err == nil {
		sasWords = crypto.SASFromBytes(material)
	}

	payloadHash := transfer.HashBytes(payload)
	meta := &transfer.Metadata{Kind: transfer.KindText, Size: int64(len(payload)), SHA256: payloadHash}
	metaBytes, _ := transfer.EncodeMetadata(meta)

	metaStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		quicConn.CloseWithError(1, "stream error")
		return verifyResult{err: fmt.Errorf("open metadata stream: %w", err)}
	}
	metaStream.Write(appendLenPrefixE2E(metaBytes))
	metaStream.Close()

	payloadStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		quicConn.CloseWithError(1, "stream error")
		return verifyResult{err: fmt.Errorf("open payload stream: %w", err)}
	}
	payloadStream.Write(payload)
	payloadStream.Close()

	doneStream, err := quicConn.AcceptStream(ctx)
	if err == nil {
		doneStream.Close()
	}
	quicConn.CloseWithError(0, "done")

	return verifyResult{sasTriggered: mergedVerify, sasWords: sasWords}
}

// runReceiverVerify is like runReceiver but accepts requireVerify and reports
// whether SAS verification would have been triggered (merged flag).
func runReceiverVerify(serverURL, code string, requireVerify bool) verifyResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := config.Default()
	channelID, words, err := crypto.ParseTransferCode(code)
	if err != nil {
		return verifyResult{err: err}
	}
	password := strings.Join(words, "-")

	epLeaf, epKey, epCertDER, err := generateTestEphemeralCert()
	if err != nil {
		return verifyResult{err: err}
	}
	myFP := network.CertFingerprint(epCertDER)

	sig, err := network.DialSignaling(context.Background(), serverURL, "")
	if err != nil {
		return verifyResult{err: err}
	}
	defer sig.Close()

	publicIPV4, publicIPV6, _ := sig.Join(channelID)

	udpConn, _ := network.BindUDP(":0")
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()
	localAddr, _ := network.LocalUDPAddr(udpConn)

	cpaceSession, myPubMsg, _ := crypto.CPaceInit(password, channelID, "receiver")

	x25519Priv, x25519Pub, _ := crypto.GenerateX25519KeyPair()
	mlkemKeys, _ := crypto.GenerateMLKEMReceiverKey()

	blob1, err := sig.RecvBlob()
	if err != nil {
		return verifyResult{err: fmt.Errorf("recv handshake blob: %w", err)}
	}
	peerCPacePub, peerX25519Pub, err := network.ParseSenderHandshakeBlob(blob1)
	if err != nil {
		return verifyResult{err: fmt.Errorf("parse sender handshake blob: %w", err)}
	}

	blob2 := network.ReceiverHandshakeBlob(myPubMsg, x25519Pub, mlkemKeys.EncapKeyBytes())
	sig.SendBlob(channelID, blob2)

	kClassical, _ := cpaceSession.CPaceFinish(peerCPacePub)

	peerX25519Key, _ := crypto.NewX25519PubFromBytes(peerX25519Pub)
	ssX25519, _ := crypto.ECDHX25519(x25519Priv, peerX25519Key)

	blob3, err := sig.RecvBlob()
	if err != nil {
		return verifyResult{err: fmt.Errorf("recv sender bundle blob: %w", err)}
	}
	kemCt, encSenderBundle, err := network.ParseSenderBundleBlob(blob3)
	if err != nil {
		return verifyResult{err: fmt.Errorf("parse sender bundle blob: %w", err)}
	}

	ssMLKEM, _ := crypto.DecapsulateMLKEM(mlkemKeys.DecapKey, kemCt)

	hybridKey := crypto.DeriveHybridBlobKey(kClassical, ssX25519, ssMLKEM)

	senderBundleBytes, _ := crypto.OpenAAD(hybridKey, channelIDAad(channelID), encSenderBundle)
	senderBundle, err := network.DecodeEndpointBundle(senderBundleBytes)
	if err != nil {
		return verifyResult{err: fmt.Errorf("decode sender bundle: %w", err)}
	}

	// Symmetric merge — same logic as cli/rx.go.
	mergedVerify := requireVerify || senderBundle.RequireVerify

	localV4, localV6, _ := network.LocalEndpoints(localAddr.Port, network.IPFamilyAny)
	portStr := fmt.Sprintf("%d", localAddr.Port)
	var publicEPV4, publicEPV6 string
	if publicIPV4 != "" {
		publicEPV4 = net.JoinHostPort(publicIPV4, portStr)
	}
	if publicIPV6 != "" {
		publicEPV6 = net.JoinHostPort(publicIPV6, portStr)
	}
	myBundle := network.EndpointBundle{
		LocalEndpointsV4: localV4,
		LocalEndpointsV6: localV6,
		PublicEndpointV4: publicEPV4,
		PublicEndpointV6: publicEPV6,
		CertFingerprint:  myFP,
		RequireVerify:    mergedVerify,
	}
	myBundleBytes, _ := network.EncodeEndpointBundle(myBundle)
	encMyBundle, _ := crypto.SealAAD(hybridKey, channelIDAad(channelID), myBundleBytes)
	sig.SendBlob(channelID, encMyBundle)

	candidatesV4, _ := network.ParseCandidates(senderBundle.CandidatesV4())
	candidatesV6, _ := network.ParseCandidates(senderBundle.CandidatesV6())
	_, err = network.HolePunchDual(ctx, ctx, mux, candidatesV4, candidatesV6, [32]byte{})
	if err != nil {
		return verifyResult{err: fmt.Errorf("UDP hole punch: %w", err)}
	}

	tlsCert := buildTLSCertFromDER(epCertDER, epKey, epLeaf)
	baseTLS := config.BuildTLSConfig(cfg)
	ln, err := network.ListenQUIC(mux, tlsCert, baseTLS, senderBundle.CertFingerprint)
	if err != nil {
		return verifyResult{err: fmt.Errorf("quic listen: %w", err)}
	}
	defer ln.Close()

	quicConn, err := ln.Accept(ctx)
	if err != nil {
		return verifyResult{err: fmt.Errorf("quic accept: %w", err)}
	}
	defer quicConn.CloseWithError(0, "done")

	// Compute SAS from TLS key material for cross-check.
	sasCtx := make([]byte, 2)
	binary.BigEndian.PutUint16(sasCtx, channelID)
	quicState := quicConn.ConnectionState()
	material, err := quicState.TLS.ExportKeyingMaterial("hermod-sas-v1", sasCtx, 32)
	var sasWords []string
	if err == nil {
		sasWords = crypto.SASFromBytes(material)
	}

	metaStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		return verifyResult{err: fmt.Errorf("accept meta stream: %w", err)}
	}
	metaBytes, err := readLenPrefixedE2E(metaStream)
	if err != nil {
		return verifyResult{err: fmt.Errorf("read metadata: %w", err)}
	}
	metaStream.Close()
	meta, err := transfer.DecodeMetadata(metaBytes)
	if err != nil {
		return verifyResult{err: err}
	}

	payloadStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		return verifyResult{err: fmt.Errorf("accept payload stream: %w", err)}
	}
	defer payloadStream.Close()

	var buf bytes.Buffer
	if err := transfer.VerifyStream(payloadStream, &buf, meta.SHA256); err != nil {
		return verifyResult{err: fmt.Errorf("integrity: %w", err)}
	}

	doneStream, err := quicConn.OpenStreamSync(ctx)
	if err == nil {
		doneStream.Close()
	}
	quicConn.CloseWithError(0, "done")

	return verifyResult{sasTriggered: mergedVerify, sasWords: sasWords, payload: buf.Bytes()}
}

// runVerifyNegotiation drives one full transfer and returns the merged verify
// flags as seen by sender and receiver.
func runVerifyNegotiation(t *testing.T, serverURL string, senderVerify, receiverVerify bool) (senderSAS, receiverSAS bool) {
	t.Helper()

	channelID, code, err := crypto.GenerateTransferCode(3)
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	password := strings.SplitN(code, "-", 2)[1]

	payload := []byte("verify-negotiation-test-payload")

	// allocReady is closed by the sender goroutine after Allocate succeeds,
	// ensuring the receiver only joins once the channel exists on the server.
	allocReady := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	var txRes, rxRes verifyResult

	go func() {
		defer wg.Done()
		txRes = runSenderVerify(serverURL, channelID, password, payload, senderVerify, allocReady)
	}()

	// Wait for sender to allocate the channel before receiver joins.
	select {
	case <-allocReady:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for sender to allocate channel")
	}

	go func() {
		defer wg.Done()
		rxRes = runReceiverVerify(serverURL, code, receiverVerify)
	}()

	wg.Wait()

	if txRes.err != nil {
		t.Fatalf("sender error: %v", txRes.err)
	}
	if rxRes.err != nil {
		t.Fatalf("receiver error: %v", rxRes.err)
	}
	if !bytes.Equal(rxRes.payload, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", rxRes.payload, payload)
	}

	// Verify both sides derived the same SAS words.
	if txRes.sasWords == nil || rxRes.sasWords == nil {
		t.Fatal("SAS words not computed on one or both sides")
	}
	if !reflect.DeepEqual(txRes.sasWords, rxRes.sasWords) {
		t.Fatalf("SAS word mismatch: sender %v, receiver %v", txRes.sasWords, rxRes.sasWords)
	}
	if len(txRes.sasWords) != 6 {
		t.Fatalf("expected 6 SAS words, got %d", len(txRes.sasWords))
	}

	return txRes.sasTriggered, rxRes.sasTriggered
}

// TestVerifyNegotiation covers all four combinations of the -v flag.
func TestVerifyNegotiation(t *testing.T) {
	cases := []struct {
		name            string
		senderVerify    bool
		receiverVerify  bool
		wantSenderSAS   bool
		wantReceiverSAS bool
	}{
		{
			name:            "neither requests verify — no SAS on either side",
			senderVerify:    false,
			receiverVerify:  false,
			wantSenderSAS:   false,
			wantReceiverSAS: false,
		},
		{
			name:            "sender requests verify — both sides must do SAS",
			senderVerify:    true,
			receiverVerify:  false,
			wantSenderSAS:   true,
			wantReceiverSAS: true,
		},
		{
			name:            "receiver requests verify — both sides must do SAS",
			senderVerify:    false,
			receiverVerify:  true,
			wantSenderSAS:   true,
			wantReceiverSAS: true,
		},
		{
			name:            "both request verify — both sides do SAS",
			senderVerify:    true,
			receiverVerify:  true,
			wantSenderSAS:   true,
			wantReceiverSAS: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Each sub-test gets its own signaling server to avoid cross-test
			// channel ID collisions and timing races.
			serverURL := startE2EServer(t)
			gotSenderSAS, gotReceiverSAS := runVerifyNegotiation(t, serverURL, tc.senderVerify, tc.receiverVerify)

			if gotSenderSAS != tc.wantSenderSAS {
				t.Errorf("sender SAS triggered = %v, want %v", gotSenderSAS, tc.wantSenderSAS)
			}
			if gotReceiverSAS != tc.wantReceiverSAS {
				t.Errorf("receiver SAS triggered = %v, want %v", gotReceiverSAS, tc.wantReceiverSAS)
			}
		})
	}
}
