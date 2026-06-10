package config_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/hermod/hermod/internal/config"
)

func generateCertPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func TestCertExpiryInfo_Empty(t *testing.T) {
	cfg := config.Default()
	notAfter, ok := config.CertExpiryInfo(cfg)
	if ok {
		t.Fatal("expected ok=false for empty cert")
	}
	if !notAfter.IsZero() {
		t.Fatal("expected zero time for empty cert")
	}
}

func TestCertExpiryInfo_InvalidPEM(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCertPEM = "not-a-valid-pem-block"
	notAfter, ok := config.CertExpiryInfo(cfg)
	if ok {
		t.Fatal("expected ok=false for invalid PEM")
	}
	if !notAfter.IsZero() {
		t.Fatal("expected zero time for invalid PEM")
	}
}

func TestCertExpiryInfo_InvalidCert(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-valid-der")}))
	notAfter, ok := config.CertExpiryInfo(cfg)
	if ok {
		t.Fatal("expected ok=false for invalid cert DER")
	}
	if !notAfter.IsZero() {
		t.Fatal("expected zero time for invalid cert DER")
	}
}

func TestCertExpiryInfo_Valid(t *testing.T) {
	cfg := config.Default()
	expected := time.Now().Add(365 * 24 * time.Hour)
	cfg.ServerCertPEM = generateCertPEM(t, expected)
	notAfter, ok := config.CertExpiryInfo(cfg)
	if !ok {
		t.Fatal("expected ok=true for valid cert")
	}
	if notAfter.Sub(expected) > time.Second {
		t.Fatalf("expected NotAfter ~%v, got %v", expected, notAfter)
	}
}

func TestLogCertExpiry_NoCert(t *testing.T) {
	cfg := config.Default()
	called := false
	config.LogCertExpiry(cfg, func(level, msg string, daysLeft int) {
		called = true
	})
	if called {
		t.Fatal("expected no log call when cert is empty")
	}
}

func TestLogCertExpiry_AboveThreshold(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCertPEM = generateCertPEM(t, time.Now().Add(365*24*time.Hour))
	var calls []string
	config.LogCertExpiry(cfg, func(level, msg string, daysLeft int) {
		calls = append(calls, level)
	})
	if len(calls) != 0 {
		t.Fatalf("expected 0 calls for 365-day cert, got %d", len(calls))
	}
}

func TestLogCertExpiry_Critical(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCertPEM = generateCertPEM(t, time.Now().Add(24*time.Hour))
	var calls []string
	config.LogCertExpiry(cfg, func(level, msg string, daysLeft int) {
		calls = append(calls, level)
	})
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0] != "CRITICAL" {
		t.Fatalf("expected CRITICAL, got %s", calls[0])
	}
}

func TestLogCertExpiry_Error(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCertPEM = generateCertPEM(t, time.Now().Add(15*24*time.Hour))
	var calls []string
	config.LogCertExpiry(cfg, func(level, msg string, daysLeft int) {
		calls = append(calls, level)
	})
	if len(calls) < 1 {
		t.Fatal("expected at least 1 call")
	}
	// 15 days matches the 30-day threshold, producing ERROR
	if calls[0] != "ERROR" {
		t.Fatalf("expected ERROR, got %s", calls[0])
	}
}

func TestLogCertExpiry_Warn(t *testing.T) {
	cfg := config.Default()
	cfg.ServerCertPEM = generateCertPEM(t, time.Now().Add(60*24*time.Hour))
	var calls []string
	config.LogCertExpiry(cfg, func(level, msg string, daysLeft int) {
		calls = append(calls, level)
	})
	if len(calls) < 1 {
		t.Fatal("expected at least 1 call")
	}
	if calls[0] != "WARN" {
		t.Fatalf("expected WARN, got %s", calls[0])
	}
}
