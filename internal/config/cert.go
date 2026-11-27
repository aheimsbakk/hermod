// Server certificate lifecycle: generation, renewal, SPKI fingerprints,
// and expiry warnings.

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// GenerateServerCert generates a self-signed X.509 cert+key and stores PEM
// strings in cfg. Uses ECDSA P-256 for fast generation and smaller signatures (L-02).
func GenerateServerCert(cfg *Config) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "hermod-server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}
	cfg.ServerCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	cfg.ServerKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return nil
}

// LoadServerTLSCert parses the PEM cert+key from cfg into a tls.Certificate.
func LoadServerTLSCert(cfg *Config) (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(cfg.ServerCertPEM), []byte(cfg.ServerKeyPEM))
}

// RenewServerCert creates a new self-signed certificate using the existing
// private key in cfg and updates the certificate PEM in cfg. The key PEM is
// left unchanged so the SPKI fingerprint stays the same — clients that pinned
// the server's public key do not need to re-run 'hermod trust'.
func RenewServerCert(cfg *Config) error {
	tlsCert, err := LoadServerTLSCert(cfg)
	if err != nil {
		return fmt.Errorf("load existing cert: %w", err)
	}
	key, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("existing private key is not an ECDSA key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "hermod-server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	cfg.ServerCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return nil
}

// PubKeyFingerprint computes the SHA-256 fingerprint of the Subject Public Key
// Info (SPKI) of a DER-encoded X.509 certificate. Unlike the certificate DER
// fingerprint, this value stays the same when the certificate is renewed with
// the same key pair.
func PubKeyFingerprint(certDER []byte) string {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ""
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// CertExpiryInfo returns the expiry time of the server certificate stored in
// cfg, and whether it could be parsed. Returns zero time and false if the cert
// is missing or unparseable.
func CertExpiryInfo(cfg *Config) (notAfter time.Time, ok bool) {
	if cfg.ServerCertPEM == "" {
		return time.Time{}, false
	}
	block, _ := pem.Decode([]byte(cfg.ServerCertPEM))
	if block == nil {
		return time.Time{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return cert.NotAfter, true
}

// certExpiryThresholds defines log-level thresholds for cert expiry warnings.
// Each entry: days remaining → (level, message).
// Checked in order; the first match applies.
var certExpiryThresholds = []struct {
	days  int
	level string
	msg   string
}{
	{7, "CRITICAL", "Server certificate expires in %d days — renew immediately to avoid outages"},
	{30, "ERROR", "Server certificate expires in %d days — schedule renewal soon"},
	{90, "WARN", "Server certificate expires in %d days — consider renewing"},
}

// LogCertExpiry logs a warning (or critical) message if the server certificate
// is approaching expiry. It does nothing if the cert cannot be parsed or is
// not configured. Callers should invoke this at server startup and periodically.
//
// Log levels used:
//   - ≤ 7 days  → CRITICAL (slog.LevelError, prefix "CRITICAL")
//   - ≤ 30 days → ERROR    (slog.LevelError)
//   - ≤ 90 days → WARN     (slog.LevelWarn)
func LogCertExpiry(cfg *Config, logFn func(level, msg string, daysLeft int)) {
	notAfter, ok := CertExpiryInfo(cfg)
	if !ok {
		return
	}
	daysLeft := int(time.Until(notAfter).Hours() / 24)
	for _, t := range certExpiryThresholds {
		if daysLeft <= t.days {
			logFn(t.level, t.msg, daysLeft)
			return
		}
	}
}
