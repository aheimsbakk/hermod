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
	"fmt"
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
	payload      []byte // receiver only
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

	sig, err := network.DialSignaling(serverURL, "")
	if err != nil {
		return verifyResult{err: fmt.Errorf("dial: %w", err)}
	}
	defer sig.Close()

	publicIP, err := sig.Allocate(channelID)
	if err != nil {
		return verifyResult{err: fmt.Errorf("allocate: %w", err)}
	}
	// Signal that the channel is allocated so the receiver can safely join.
	close(allocReady)

	udpConn, err := network.BindUDP(":0")
	if err != nil {
		return verifyResult{err: fmt.Errorf("bind udp: %w", err)}
	}
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()

	localAddr, _ := network.LocalUDPAddr(udpConn)

	cpaceSession, myPubMsg, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		return verifyResult{err: fmt.Errorf("cpace init: %w", err)}
	}

	if err := sig.WaitReady(); err != nil {
		return verifyResult{err: fmt.Errorf("wait ready: %w", err)}
	}

	cpaceMsgBytes, _ := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	sig.SendBlob(channelID, cpaceMsgBytes)

	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return verifyResult{err: fmt.Errorf("recv cpace: %w", err)}
	}
	peerCPaceMsg, _ := network.DecodeCPaceMsg(peerCPaceMsgBytes)
	kClassical, err := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)
	if err != nil {
		return verifyResult{err: fmt.Errorf("cpace finish: %w", err)}
	}

	localEPs, _ := network.LocalEndpoints(localAddr.Port)
	bundle := network.EndpointBundle{
		LocalEndpoints:  localEPs,
		PublicEndpoint:  fmt.Sprintf("%s:%d", publicIP, localAddr.Port),
		CertFingerprint: myFP,
		RequireVerify:   requireVerify,
	}
	bundleBytes, _ := network.EncodeEndpointBundle(bundle)
	encBundle, _ := crypto.Seal(kClassical, bundleBytes)
	sig.SendBlob(channelID, encBundle)

	encPeerBundle, err := sig.RecvBlob()
	if err != nil {
		return verifyResult{err: fmt.Errorf("recv peer bundle: %w", err)}
	}
	peerBundleBytes, err := crypto.Open(kClassical, encPeerBundle)
	if err != nil {
		return verifyResult{err: fmt.Errorf("decrypt peer bundle: %w", err)}
	}
	peerBundle, err := network.DecodeEndpointBundle(peerBundleBytes)
	if err != nil {
		return verifyResult{err: fmt.Errorf("decode peer bundle: %w", err)}
	}

	// Symmetric merge — same logic as cli/tx.go.
	mergedVerify := requireVerify || peerBundle.RequireVerify

	allCandidates := []string{peerBundle.PublicEndpoint}
	allCandidates = append(allCandidates, peerBundle.LocalEndpoints...)
	candidates, _ := network.ParseCandidates(allCandidates)

	punchResult, err := network.HolePunch(ctx, mux, candidates, [4]byte{})
	if err != nil {
		return verifyResult{err: fmt.Errorf("hole punch: %w", err)}
	}

	time.Sleep(200 * time.Millisecond)

	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCert := buildTLSCertFromDER(epCertDER, epKey, epLeaf)
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	quicConn, err := network.DialQUIC(ctx, mux, punchResult.PeerAddr, tlsCfg, peerBundle.CertFingerprint)
	if err != nil {
		return verifyResult{err: fmt.Errorf("quic dial: %w", err)}
	}

	payloadHash := transfer.HashBytes(payload)
	meta := &transfer.Metadata{Kind: transfer.KindText, Size: int64(len(payload)), SHA256: payloadHash}
	metaBytes, _ := transfer.EncodeMetadata(meta)

	metaStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		quicConn.CloseWithError(1, "stream error")
		return verifyResult{err: fmt.Errorf("open meta stream: %w", err)}
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

	return verifyResult{sasTriggered: mergedVerify}
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

	sig, err := network.DialSignaling(serverURL, "")
	if err != nil {
		return verifyResult{err: err}
	}
	defer sig.Close()

	publicIP, _ := sig.Join(channelID)

	udpConn, _ := network.BindUDP(":0")
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()
	localAddr, _ := network.LocalUDPAddr(udpConn)

	cpaceSession, myPubMsg, _ := crypto.CPaceInit(password, channelID, "receiver")

	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return verifyResult{err: fmt.Errorf("recv cpace: %w", err)}
	}
	peerCPaceMsg, _ := network.DecodeCPaceMsg(peerCPaceMsgBytes)

	cpaceMsgBytes, _ := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	sig.SendBlob(channelID, cpaceMsgBytes)

	kClassical, _ := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)

	encSenderBundle, _ := sig.RecvBlob()
	senderBundleBytes, _ := crypto.Open(kClassical, encSenderBundle)
	senderBundle, err := network.DecodeEndpointBundle(senderBundleBytes)
	if err != nil {
		return verifyResult{err: fmt.Errorf("decode sender bundle: %w", err)}
	}

	// Symmetric merge — same logic as cli/rx.go.
	mergedVerify := requireVerify || senderBundle.RequireVerify

	localEPs, _ := network.LocalEndpoints(localAddr.Port)
	myBundle := network.EndpointBundle{
		LocalEndpoints:  localEPs,
		PublicEndpoint:  fmt.Sprintf("%s:%d", publicIP, localAddr.Port),
		CertFingerprint: myFP,
		RequireVerify:   mergedVerify,
	}
	myBundleBytes, _ := network.EncodeEndpointBundle(myBundle)
	encMyBundle, _ := crypto.Seal(kClassical, myBundleBytes)
	sig.SendBlob(channelID, encMyBundle)

	allCandidates := []string{senderBundle.PublicEndpoint}
	allCandidates = append(allCandidates, senderBundle.LocalEndpoints...)
	candidates, _ := network.ParseCandidates(allCandidates)

	_, err = network.HolePunch(ctx, mux, candidates, [4]byte{})
	if err != nil {
		return verifyResult{err: fmt.Errorf("hole punch: %w", err)}
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

	return verifyResult{sasTriggered: mergedVerify, payload: buf.Bytes()}
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
