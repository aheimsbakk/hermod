# Cryptography & Protocol Compliance Report

Audited: 2026-06-14
Scope: `internal/crypto`, `internal/network` (handshake, network, stun), `internal/server` (udp_reflect, server), `internal/cli` (tx, rx)
All tests pass for these packages.

## Summary

The crypto exchange implementation is **fully compliant** with the architecture in `BLUEPRINT.md` and the wire protocol in `docs/protocol.md`. The encryption is sound. Minor documentation ambiguity found (non-critical).

---

## Layer-by-Layer Verification

### 1. CPace PAKE (Phase 2)

| Property | Expected (arch/protocol) | Actual (code) | Status |
|----------|--------------------------|---------------|--------|
| Curve | P-256 (NIST) | `ecdh.P256()` | ✓ |
| Hash-to-curve | `P256_XMD:SHA-256_SSWU_RO_` (RFC 9380) | `hashToCurveP256` — full RFC 9380 impl | ✓ |
| DST encoding | `hermod-cpace-v1:<channelID>:<password>` | `p256DST()` — exact match | ✓ |
| Generator message | `"sender:receiver"` (fixed role tag) | `cpaceGenerator` — exact match | ✓ |
| Key derivation | `SHA-256(iskX \|\| pubSender \|\| pubReceiver)` | `CPaceSession.CPaceFinish` — role-ordered transcript | ✓ |
| Role binding | Role in ISK transcript prevents cross-role composition (RFC 9496) | `TestCPaceRoleSeparation` passes | ✓ |
| Point validation | On-curve check | `ecdh.NewPublicKey` validates curve membership | ✓ |
| Wrong password | Produces different key → AES-GCM tag mismatch | `TestCPaceWrongPassword` passes | ✓ |

RFC 9380 compliance verified against published test vectors (J.1.1, K.1).

### 2. Hybrid KEM (Phase 3 — X25519 + ML-KEM-768)

| Blob | Expected (protocol) | Actual (code) | Status |
|------|-------------------|---------------|--------|
| Blob 1 (sender→receiver) | 65 CPace + 32 X25519 = **97 bytes** | `SenderHandshakeBlob` = 97 bytes | ✓ |
| Blob 2 (receiver→sender) | 65 CPace + 32 X25519 + 1184 MLKEM ek = **1281 bytes** | `ReceiverHandshakeBlob` = 1281 bytes | ✓ |
| Blob 3 (sender→receiver) | 1088 KEM ct + AES-256-GCM bundle = variable | `SenderBundleBlob` | ✓ |
| Blob 4 (receiver→sender) | AES-256-GCM bundle = variable | Raw encrypted bundle | ✓ |

### 3. HybridBlobKey Derivation

```
Expected: SHA-256(kClassical || ssX25519 || ssMLKEM)
Actual:  DeriveHybridBlobKey — SHA-256 concatenation combiner, exactly as specified ✓
```

**Security assertion**: "at least as strong as the strongest pillar". Three independent pillars (CPace P-256, X25519, ML-KEM-768) combined via split combiner. Post-quantum security even if P-256 falls. ✓

### 4. AES-256-GCM with AAD

| Property | Expected | Actual | Status |
|----------|----------|--------|--------|
| Algorithm | AES-256-GCM | `crypto/aes` + `crypto/cipher` stdlib | ✓ |
| Key size | 32 bytes | 32 bytes from `DeriveHybridBlobKey` | ✓ |
| AAD | Channel ID (2-byte big-endian) | `channelIDAad()` = 2-byte big-endian | ✓ |
| Nonce | Random, 12 bytes | `rand.Reader`, 12 bytes | ✓ |
| Output | nonce \|\| ciphertext \|\| tag | `SealAAD` prepends nonce | ✓ |
| Tamper detection | GCM authentication tag | `TestOpenAADTamperedCiphertext` passes | ✓ |

### 5. Endpoint Bundle Structure

All fields match between `EndpointBundle` struct and the JSON schema in protocol.md and BLUEPRINT.md:

- `local_endpoints_v4` / `local_endpoints_v6` — split by family ✓
- `public_endpoint_v4` / `public_endpoint_v6` — server-reflexive addresses ✓
- `public_key_fingerprint` — SPKI SHA-256 hex ✓
- `require_verify` — merged as `local_verify || peer.require_verify` ✓

### 6. UDP External Address Discovery (Phase 1.5)

| Step | Expected | Actual | Status |
|------|----------|--------|--------|
| Phase 1: cookie request | client `[0x10]` → server | `reflectCookieMagic = 0x10`, 1-byte probe | ✓ |
| Phase 1 response | server `[0x10][HMAC[:8]]` (9 bytes) | `computeCookie` = HMAC-SHA256(key, IP)[:8] | ✓ |
| Phase 2: cookie echo | client `[0x10][cookie]` (9 bytes) | Echo sent, server calls `verifyCookie` | ✓ |
| Phase 2 response | server `[family][IP][port]` (7-19 bytes) | `encodeExternalAddress` | ✓ |
| Anti-amplification | Phase 1 rate-limited (10/5), Phase 2 not rate-limited | `NewRateLimiter(10, 5)` for phase 1 only | ✓ |
| Key rotation | Daily, 5-min grace for old key | `rotateKey()` at startup + every 24h; grace via `oldKey` | ✓ |

### 7. UDP Hole Punch (Phase 4)

| Property | Expected | Actual | Status |
|----------|----------|--------|--------|
| Probe format | `[0x01][hash[0:7]]` — 8 bytes | `probeMarker(0x01) + nonce[0:7]` | ✓ |
| Ack format | `[0x01][hash[8:15]]` — 8 bytes | `probeMarker(0x01) + nonce[8:15]` | ✓ |
| Nonce derivation | `SHA-256(hybridKey + "hermod-holepunch-v1")` | `holePunchNonce()` — exact match | ✓ |
| Two-phase (v6 first, v4 fallback) | IPv6 5s timeout, IPv4 remaining | `HolePunchDual` | ✓ |
| Probe context | Probes continue after HolePunch returns (NAT keepalive) | `probeCtx` separate from `ctx`, cancelled after QUIC dial | ✓ |
| Constant-time comparison | `subtle.ConstantTimeCompare` | Used for both probe detection and ack detection | ✓ |

**Note**: protocol.md says "bytes 1–7: hash[8:14]" for ack, but the code uses `nonce[8:15]` (7 elements: indices 8-14). In Go slice notation, `hash[8:14]` is only 6 elements. The spec notation appears to use inclusive ranges (hash[8:14] = elements 8 through 14 = 7 elements), which is consistent with the code. Minor notation difference, not a bug.

### 8. QUIC Transport (Phase 5)

| Property | Expected | Actual | Status |
|----------|----------|--------|--------|
| TLS version | 1.3 | Enforced by quic-go | ✓ |
| ALPN | `hermod-p2p` | Set in both `DialQUIC` and `ListenQUIC` | ✓ |
| Mutual TLS | Receiver uses `RequireAnyClientCert` | `ListenQUIC` sets `ClientAuth = tls.RequireAnyClientCert` | ✓ |
| SPKI pinning | SHA-256 of peer's SPKI via `VerifyPeerCertificate` | `makeCertPinner()` | ✓ |
| Ephemeral cert | ECDSA P-256, 2h validity | `generateEphemeralCert()` | ✓ |
| Idle timeout | 30s | `MaxIdleTimeout: 30 * time.Second` | ✓ |
| Keep-alive | 5s | `KeepAlivePeriod: 5 * time.Second` | ✓ |

### 9. Payload Transfer (Phase 6)

| Stream | Expected | Actual | Status |
|--------|----------|--------|--------|
| 0 — SAS | 1-byte confirm/reject (0x01/0x00) | `performSASCoordinated` | ✓ |
| 1 — Metadata | 4-byte length-prefixed JSON | `appendLenPrefix` + JSON marshal | ✓ |
| 2 — Payload | Raw bytes, SHA-256 via TeeReader in parallel | `transfer.HashStream` with `io.TeeReader` | ✓ |
| 3 — Trailing hash | 4-byte length-prefixed hex SHA-256 | `appendLenPrefix([]byte(payloadHash))` | ✓ |
| 4 — Completion ack | Empty stream, receiver opens | `ackStream.OpenStreamSync` → close | ✓ |

### 10. Transfer Code Generation

| Property | Expected | Actual | Status |
|----------|----------|--------|--------|
| Format | `<channelID>-<word>-<word>-<word>` | `fmt.Sprintf("%d-%s", channelID, words)` | ✓ |
| Wordlist | EFF Short Wordlist 1 (1296 entries) | `effShortWordlist` — 1296 entries, no duplicates | ✓ |
| RNG bias | Rejection sampling on uint16 → no modulo bias | `randomWordIndex()` — rejection sampling | ✓ |
| Min words | 3 | Clamped to 3 in `GenerateTransferCode` | ✓ |
| Channel ID | Random uint16 | `crypto/rand` → `binary.BigEndian.Uint16` | ✓ |

### 11. Security Controls — Signaling Server

| Control | Expected | Actual | Status |
|---------|----------|--------|--------|
| Max blobs per channel | 10 | `DefaultMaxBlobsPerChannel = 10` | ✓ |
| Max CPace failures | 3 | `DefaultMaxCPaceFailures = 3` | ✓ |
| Rate limiting | Token bucket per IP, HMAC-salted, daily key rotation | `NewRateLimiter` with HMAC-SHA256 salt, daily rotation, 10-min cleanup | ✓ |
| WebSocket origin check | Reject browser cross-origin | `r.Header.Get("Origin") == ""` | ✓ |
| Channel TTL | Configurable, default 600s | Passed from `--ttl` flag | ✓ |
| Per-IP channel cap | Default 100 | `DefaultMaxChannelsPerIP = 100` | ✓ |

---

## Encryption Soundness

1. **Randomness sources**: All use `crypto/rand.Reader` (key generation, nonces, scalar generation, transfer code randomness). No `math/rand` or weak PRNG in any cryptographic path. ✓

2. **Constant-time operations**: Probe/ack matching uses `subtle.ConstantTimeCompare`. Certificate fingerprint pinning uses `subtle.ConstantTimeCompare`. HMAC cookie verification uses `hmac.Equal`. ✓

3. **Key hygiene**: CPace scalars are 32-byte ephemeral values generated via rejection sampling. X25519 and ML-KEM-768 keys are ephemeral per session. QUIC certs are ephemeral (2h validity). No keys are persisted except the server's long-term TLS key (config.yaml, 0o600 permissions). ✓

4. **Domain separation**: CPace DST includes the protocol identifier (`hermod-cpace-v1:`), channel ID, and password. ISK derivation includes role (`sender`/`receiver`) in the transcript. AAD binds channel ID to endpoint bundles. SAS EKM context includes channel ID bytes. ✓

5. **Post-quantum resilience**: ML-KEM-768 (FIPS 203) provides PQ security for the signaling relay phase. Even if P-256 and X25519 are broken by quantum cryptanalysis, the HybridBlobKey retains ML-KEM-768's security. ✓

6. **Replay protection**: Channel ID is bound as AAD in AES-GCM. Endpoint bundles encrypted for a specific channel ID cannot be replayed in a different session. ✓

7. **Certificate pinning**: SPKI (Subject Public Key Info) pinning is used rather than cert DER pinning, so certificate renewal with the same key pair does not invalidate pinned fingerprints. This applies to both server trust (`hermod trust`) and peer QUIC mutual auth. ✓

---

## Issues Found

**Minor — documentation ambiguity only, no code bug.**

- **protocol.md §NAT hole punching**: The ack range is written as `hash[8:14]` which in Go half-open slice notation is 6 elements, but the code uses `nonce[8:15]` which is 7 elements. The spec appears to use inclusive range notation (8 through 14 = 7 elements), matching the implementation. Recommend clarifying the notation to `hash[8:15]` (Go-style half-open) to avoid confusion.
  - Location: `docs/protocol.md` line 296
  - Actual code: `network/network.go` line 256

---

## Test Coverage

| Package | Tests | Key tests |
|---------|-------|-----------|
| `internal/crypto` | 26 | CPace exchange + wrong password + role separation; X25519 ECDH; ML-KEM round trip + wrong key; HybridBlobKey derivation; AES-GCM seal/open + tampered ciphertext; SAS determinism; Identicon; Transfer code gen/parse; **RFC 9380 compliance (5 test vectors + sqrtRatio contract)** |
| `internal/network` | 20 | Endpoint bundle round-trip; Handshake blob serialization; SPKI fingerprint; UDP bind; Packet mux; Hole punch (indirect); Signaling allocate/join/error paths; Duplicate receiver rejection; Context cancellation |
| `internal/server` | 14 | Channel allocate/exists/expiry; Per-IP cap; CPace failure limit enforcement; Blob limit; Rate limiter; Join rate limiting; Non-existent channel rejection; Cert endpoint |

All tests pass.
