// TLS curve and cipher suite name mapping for the stored preferences.

package config

import (
	"crypto/tls"
)

// TLSCurveIDs maps curve name strings to tls.CurveID values.
func TLSCurveIDs(names []string) []tls.CurveID {
	table := map[string]tls.CurveID{
		"X25519MLKEM768": tls.X25519MLKEM768,
		"X25519":         tls.X25519,
		"CurveP256":      tls.CurveP256,
		"CurveP384":      tls.CurveP384,
		"CurveP521":      tls.CurveP521,
	}
	out := make([]tls.CurveID, 0, len(names))
	for _, n := range names {
		if id, ok := table[n]; ok {
			out = append(out, id)
		}
	}
	return out
}

// TLSCipherSuiteIDs maps cipher suite name strings to uint16 IDs.
func TLSCipherSuiteIDs(names []string) []uint16 {
	table := map[string]uint16{
		"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
	}
	out := make([]uint16, 0, len(names))
	for _, n := range names {
		if id, ok := table[n]; ok {
			out = append(out, id)
		}
	}
	return out
}

// BuildTLSConfig constructs a *tls.Config from the stored preferences.
func BuildTLSConfig(cfg *Config) *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: TLSCurveIDs(cfg.TLS.PreferCurves),
		CipherSuites:     TLSCipherSuiteIDs(cfg.TLS.CipherSuites),
	}
}
