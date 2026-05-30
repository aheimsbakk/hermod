// Package e2e: integration test for full file transfer flow.
package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/crypto"
	"github.com/hermod/hermod/internal/network"
	"github.com/hermod/hermod/internal/server"
	"github.com/hermod/hermod/pkg/transfer"
)

// startE2EServer starts a local signaling server and returns its wss:// URL.
func startE2EServer(t *testing.T) string {
	t.Helper()
	cfg := config.Default()
	if err := config.GenerateServerCert(cfg); err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	tlsCert, err := config.LoadServerTLSCert(cfg)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	store := server.NewMemoryStore()
	rl := server.NewRateLimiter(100, 1000)
	srv := server.NewServer(store, rl, 60*time.Second, server.DefaultMaxBlobsPerChannel, server.DefaultMaxCPaceFailures, nil, slog.Default())

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.ListenAndServe(ctx, addr, tlsCfg)

	for i := 0; i < 30; i++ {
		time.Sleep(50 * time.Millisecond)
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return "wss://" + addr
		}
	}
	t.Fatal("server did not start")
	return ""
}

// TestFullTransferText tests sending a text payload end-to-end.
func TestFullTransferText(t *testing.T) {
	serverURL := startE2EServer(t)
	testText := "Hello, Hermod!"
	testFullTransfer(t, serverURL, transfer.KindText, testText, []byte(testText))
}

// TestFullTransferFile tests sending a file payload end-to-end.
func TestFullTransferFile(t *testing.T) {
	serverURL := startE2EServer(t)

	// Create a test file
	content := make([]byte, 1024)
	rand.Read(content)
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.bin")
	os.WriteFile(srcPath, content, 0o644)

	testFullTransferFile(t, serverURL, srcPath, content)
}

// testFullTransfer performs a complete CPace + QUIC text transfer.
func testFullTransfer(t *testing.T, serverURL string, kind transfer.Kind, input string, expectedPayload []byte) {
	t.Helper()

	// Generate transfer code
	channelID, code, err := crypto.GenerateTransferCode(3)
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	password := strings.SplitN(code, "-", 2)[1]
	password = strings.ReplaceAll(password, "-", "-")

	var wg sync.WaitGroup
	wg.Add(2)
	var txErr, rxErr error
	var receivedPayload []byte

	// Sender goroutine
	go func() {
		defer wg.Done()
		txErr = runSender(serverURL, channelID, password, kind, input, expectedPayload)
	}()

	// Receiver goroutine (slight delay to let sender allocate first)
	time.Sleep(100 * time.Millisecond)
	go func() {
		defer wg.Done()
		receivedPayload, rxErr = runReceiver(serverURL, code)
	}()

	wg.Wait()

	if txErr != nil {
		t.Fatalf("sender error: %v", txErr)
	}
	if rxErr != nil {
		t.Fatalf("receiver error: %v", rxErr)
	}
	if !bytes.Equal(receivedPayload, expectedPayload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(receivedPayload), len(expectedPayload))
	}
}

func testFullTransferFile(t *testing.T, serverURL, srcPath string, content []byte) {
	t.Helper()
	channelID, code, _ := crypto.GenerateTransferCode(3)
	password := strings.SplitN(code, "-", 2)[1]

	var wg sync.WaitGroup
	wg.Add(2)
	var txErr, rxErr error
	var receivedPayload []byte

	go func() {
		defer wg.Done()
		txErr = runSender(serverURL, channelID, password, transfer.KindFile, srcPath, content)
	}()

	time.Sleep(100 * time.Millisecond)
	go func() {
		defer wg.Done()
		receivedPayload, rxErr = runReceiver(serverURL, code)
	}()

	wg.Wait()
	if txErr != nil {
		t.Fatalf("sender: %v", txErr)
	}
	if rxErr != nil {
		t.Fatalf("receiver: %v", rxErr)
	}

	sum := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(sum[:])
	gotSum := sha256.Sum256(receivedPayload)
	gotHash := hex.EncodeToString(gotSum[:])
	if expectedHash != gotHash {
		t.Fatalf("SHA-256 mismatch: got %s, want %s", gotHash, expectedHash)
	}
}

// runSender performs the full sender flow.
func runSender(serverURL string, channelID uint16, password string, kind transfer.Kind, input string, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := config.Default()

	// Generate ephemeral cert
	epLeaf, epKey, epCertDER, err := generateTestEphemeralCert()
	if err != nil {
		return fmt.Errorf("gen cert: %w", err)
	}
	myFP := network.CertFingerprint(epCertDER)

	sig, err := network.DialSignaling(serverURL, "")
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer sig.Close()

	publicIP, err := sig.Allocate(channelID)
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}

	udpConn, err := network.BindUDP(":0")
	if err != nil {
		return fmt.Errorf("bind udp: %w", err)
	}
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()

	localAddr, _ := network.LocalUDPAddr(udpConn)

	cpaceSession, myPubMsg, err := crypto.CPaceInit(password, channelID, "sender")
	if err != nil {
		return fmt.Errorf("cpace init: %w", err)
	}

	// Wait for receiver
	if err := sig.WaitReady(); err != nil {
		return fmt.Errorf("wait ready: %w", err)
	}

	// CPace exchange
	cpaceMsgBytes, _ := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	sig.SendBlob(channelID, cpaceMsgBytes)

	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return fmt.Errorf("recv cpace: %w", err)
	}
	peerCPaceMsg, _ := network.DecodeCPaceMsg(peerCPaceMsgBytes)
	kClassical, err := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)
	if err != nil {
		return fmt.Errorf("cpace finish: %w", err)
	}

	// Endpoint exchange
	localEPs, _ := network.LocalEndpoints(localAddr.Port)
	publicEP := fmt.Sprintf("%s:%d", publicIP, localAddr.Port)
	bundle := network.EndpointBundle{
		LocalEndpoints:  localEPs,
		PublicEndpoint:  publicEP,
		CertFingerprint: myFP,
	}
	bundleBytes, _ := network.EncodeEndpointBundle(bundle)
	encBundle, _ := crypto.Seal(kClassical, bundleBytes)
	sig.SendBlob(channelID, encBundle)

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

	allCandidates := []string{peerBundle.PublicEndpoint}
	allCandidates = append(allCandidates, peerBundle.LocalEndpoints...)
	candidates, _ := network.ParseCandidates(allCandidates)

	punchResult, err := network.HolePunch(ctx, mux, candidates)
	if err != nil {
		return fmt.Errorf("hole punch: %w", err)
	}

	// Give receiver time to set up QUIC listener after hole punch.
	time.Sleep(200 * time.Millisecond)

	// Build TLS cert for QUIC
	tlsCfg := config.BuildTLSConfig(cfg)
	tlsCert := buildTLSCertFromDER(epCertDER, epKey, epLeaf)
	tlsCfg.Certificates = []tls.Certificate{tlsCert}

	quicConn, err := network.DialQUIC(ctx, mux, punchResult.PeerAddr, tlsCfg, peerBundle.CertFingerprint)
	if err != nil {
		return fmt.Errorf("quic dial: %w", err)
	}

	// Build metadata
	payloadHash := transfer.HashBytes(payload)
	meta := &transfer.Metadata{
		Kind:   kind,
		Size:   int64(len(payload)),
		SHA256: payloadHash,
	}
	if kind == transfer.KindFile {
		meta.Name = filepath.Base(input)
	}

	// Send metadata
	metaStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		quicConn.CloseWithError(1, "stream error")
		return fmt.Errorf("open meta stream: %w", err)
	}
	metaBytes, _ := transfer.EncodeMetadata(meta)
	metaStream.Write(appendLenPrefixE2E(metaBytes))
	metaStream.Close()

	// Send payload
	payloadStream, err := quicConn.OpenStreamSync(ctx)
	if err != nil {
		quicConn.CloseWithError(1, "stream error")
		return fmt.Errorf("open payload stream: %w", err)
	}
	if _, err := payloadStream.Write(payload); err != nil {
		quicConn.CloseWithError(1, "write error")
		return fmt.Errorf("write payload: %w", err)
	}
	payloadStream.Close()

	// Accept a "done" stream from receiver to know it has finished reading.
	doneStream, err := quicConn.AcceptStream(ctx)
	if err == nil {
		doneStream.Close()
	}
	quicConn.CloseWithError(0, "done")
	return nil
}

// runReceiver performs the full receiver flow and returns the received bytes.
func runReceiver(serverURL, code string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := config.Default()
	channelID, words, err := crypto.ParseTransferCode(code)
	if err != nil {
		return nil, err
	}
	password := strings.Join(words, "-")

	epLeaf, epKey, epCertDER, err := generateTestEphemeralCert()
	if err != nil {
		return nil, err
	}
	myFP := network.CertFingerprint(epCertDER)

	sig, err := network.DialSignaling(serverURL, "")
	if err != nil {
		return nil, err
	}
	defer sig.Close()

	publicIP, _ := sig.Join(channelID)

	udpConn, _ := network.BindUDP(":0")
	mux := network.NewPacketMux(udpConn)
	defer mux.Close()
	localAddr, _ := network.LocalUDPAddr(udpConn)

	cpaceSession, myPubMsg, _ := crypto.CPaceInit(password, channelID, "receiver")

	// Exchange CPace
	peerCPaceMsgBytes, err := sig.RecvBlob()
	if err != nil {
		return nil, fmt.Errorf("recv cpace: %w", err)
	}
	peerCPaceMsg, _ := network.DecodeCPaceMsg(peerCPaceMsgBytes)

	cpaceMsgBytes, _ := network.EncodeCPaceMsg(network.CPaceMsg{PubMsg: myPubMsg})
	sig.SendBlob(channelID, cpaceMsgBytes)

	kClassical, _ := cpaceSession.CPaceFinish(peerCPaceMsg.PubMsg)

	// Exchange endpoints
	encSenderBundle, _ := sig.RecvBlob()
	senderBundleBytes, _ := crypto.Open(kClassical, encSenderBundle)
	senderBundle, _ := network.DecodeEndpointBundle(senderBundleBytes)

	localEPs, _ := network.LocalEndpoints(localAddr.Port)
	myBundle := network.EndpointBundle{
		LocalEndpoints:  localEPs,
		PublicEndpoint:  fmt.Sprintf("%s:%d", publicIP, localAddr.Port),
		CertFingerprint: myFP,
	}
	myBundleBytes, _ := network.EncodeEndpointBundle(myBundle)
	encMyBundle, _ := crypto.Seal(kClassical, myBundleBytes)
	sig.SendBlob(channelID, encMyBundle)

	allCandidates := []string{senderBundle.PublicEndpoint}
	allCandidates = append(allCandidates, senderBundle.LocalEndpoints...)
	candidates, _ := network.ParseCandidates(allCandidates)

	_, err = network.HolePunch(ctx, mux, candidates)
	if err != nil {
		return nil, fmt.Errorf("hole punch: %w", err)
	}

	// QUIC listen
	tlsCert := buildTLSCertFromDER(epCertDER, epKey, epLeaf)
	baseTLS := config.BuildTLSConfig(cfg)
	ln, err := network.ListenQUIC(mux, tlsCert, baseTLS, senderBundle.CertFingerprint)
	if err != nil {
		return nil, fmt.Errorf("quic listen: %w", err)
	}
	defer ln.Close()

	quicConn, err := ln.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("quic accept: %w", err)
	}
	defer quicConn.CloseWithError(0, "done")

	// Read metadata
	metaStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept meta stream: %w", err)
	}
	metaBytes, err := readLenPrefixedE2E(metaStream)
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}
	metaStream.Close()
	meta, err := transfer.DecodeMetadata(metaBytes)
	if err != nil {
		return nil, err
	}

	// Read payload
	payloadStream, err := quicConn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept payload stream: %w", err)
	}
	defer payloadStream.Close()

	var buf bytes.Buffer
	if err := transfer.VerifyStream(payloadStream, &buf, meta.SHA256); err != nil {
		return nil, fmt.Errorf("integrity: %w", err)
	}
	payloadStream.Close()

	// Signal sender that we are done reading.
	doneStream, err := quicConn.OpenStreamSync(ctx)
	if err == nil {
		doneStream.Close()
	}
	quicConn.CloseWithError(0, "done")

	return buf.Bytes(), nil
}

func appendLenPrefixE2E(data []byte) []byte {
	out := make([]byte, 4+len(data))
	out[0] = byte(len(data) >> 24)
	out[1] = byte(len(data) >> 16)
	out[2] = byte(len(data) >> 8)
	out[3] = byte(len(data))
	copy(out[4:], data)
	return out
}

func readLenPrefixedE2E(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := readFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
	if length > 1<<20 {
		return nil, fmt.Errorf("too large: %d", length)
	}
	buf := make([]byte, length)
	if _, err := readFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			if total == len(buf) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}
