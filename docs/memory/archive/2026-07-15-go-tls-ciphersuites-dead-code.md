# Go tls.Config.CipherSuites is dead code for TLS 1.3

## Finding

`config.BuildTLSConfig` sets `MinVersion: tls.VersionTLS13` and populates
`tls.Config.CipherSuites` with named TLS 1.3 cipher suite IDs. Go ignores
`CipherSuites` for TLS 1.3 — it is only consulted for TLS 1.2 and below.
Go uses its own hardcoded preference list regardless.

## RFC 8446 Mandatory-to-Implement Suites (Section 9.1)

A TLS-compliant application **MUST** implement `TLS_AES_128_GCM_SHA256` and
**SHOULD** implement `TLS_AES_256_GCM_SHA384` and
`TLS_CHACHA20_POLY1305_SHA256`. Only these three are mandatory/SHOULD; the
other two (`TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`) are
optional. The RFC does not prescribe a client preference order — it defers
to the implementation (Section 4.1.2: "in descending order of client
preference").

## Impact

The `cipher_suites` config option and `TLSCipherSuiteIDs()` function have no
effect on a TLS 1.3-only connection. The user-facing config is misleading.

The project's default config declares `TLS_AES_256_GCM_SHA384` as the top
preference and omits `TLS_AES_128_GCM_SHA256` entirely, but Go silently uses
its own hardcoded order:
1. `TLS_AES_128_GCM_SHA256` (MUST, but not in config)
2. `TLS_AES_256_GCM_SHA384`
3. `TLS_CHACHA20_POLY1305_SHA256`

## Fix (Go 1.23+)

Use `tls.Config.CipherSuitePreferences` instead:

```go
&tls.Config{
    MinVersion:               tls.VersionTLS13,
    CurvePreferences:         TLSCurveIDs(cfg.TLS.PreferCurves),
    CipherSuitePreferences: tls.CipherSuitePreferences{
        CipherSuites: TLSCipherSuiteIDs(cfg.TLS.CipherSuites),
    },
}
```

`CipherSuites` on `tls.Config` can be removed or flagged `@deprecated`.
