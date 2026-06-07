# Security Audit: Hermod v0.12.0

**Audit date:** 2026-06-07  
**Tool used:** deepseek-v4-flash  
**Scope:** Full source code review (Go 1.25, quic-go, gorilla/websocket)  
**Previous audits found in repo:** `docs/audits/2026-05-29-audit-sonet46.md` and `docs/audits/audit-deepseek-v4-flash-max.md` — ignored per instructions.

---

## Threat Model Summary

Hermod is a peer-to-peer file/text transfer tool. A signaling server brokers the connection but never sees payload data. The threat model assumes:

- The signaling server is **untrusted** for payload confidentiality.
- The signaling server is **honest-but-curious** for signaling: it must function correctly, but may try to observe metadata.
- Peers do not trust each other until CPace PAKE + SAS verification completes.
- The network between peers and the signaling server is subject to eavesdropping and active MitM.

---

## Findings by Severity

---

### P1 — Fix next

#### 1. TLS server identity is not verified during `hermod trust` bootstrap

**File:** `internal/network/signaling.go`, lines 236–237  
**File:** `internal/cli/trust.go`, lines 66–69

The `trust` command fetches the server certificate with `InsecureSkipVerify: true` and no custom `VerifyPeerCertificate`. The connection is encrypted (TLS 1.3), but the server's identity is not verified. This is trust-on-first-use (TOFU).

The `--fingerprint` flag allows the user to supply a previously known fingerprint, which is checked *after* the connection closes. But the initial fetch itself has no server identity check.

**Risk:** A MitM attacker on the first connection can present their own certificate, and the fetched (attacker-controlled) fingerprint gets pinned. All subsequent connections are then secured against the attacker but pinned to the attacker's cert.

**Mitigation:** When `--fingerprint` is set, verify it *during* the TLS handshake (use `VerifyPeerCertificate`), not after. Document that `trust` without `--fingerprint` must only be run over a trusted network.

**Status: Fixed** in commit 3d16227 — `VerifyPeerCertificate` checks the fingerprint during the TLS handshake when `--fingerprint` is set. The post-hoc comparison in `trust.go` was removed as redundant.

---

#### 2. Signaling client always sets `InsecureSkipVerify: true` without fallback chain validation

**File:** `internal/network/signaling.go`, lines 48–49

```go
tlsCfg := &tls.Config{
    InsecureSkipVerify: true,
}
```

When `pinnedFingerprint` is non-empty, a custom `VerifyPeerCertificate` callback provides cert-pinning security. When `pinnedFingerprint` is empty (e.g., `trust` command), there is no certificate validation at all — not even the standard CA chain, hostname, or expiry checks.

**Risk:** The TLS tunnel provides encryption but the peer's identity is not authenticated.

**Recommendation:** When `pinnedFingerprint` is empty, still perform standard TLS verification. Use `InsecureSkipVerify: true` only when cert pinning is active.

**Status: Won't fix — intended functionality.** The signaling server uses a self-signed certificate, so CA chain verification would always reject it. The TOFU bootstrap phase (`trust` without `--fingerprint`) is intentionally unauthenticated — the connection is encrypted but identity is not verified. Operational guidance already documents that this must run over a trusted network. When `pinnedFingerprint` is set (normal tx/rx), `VerifyPeerCertificate` provides strong identity verification via cert pinning.

---

#### 3. CPace hash-to-curve uses `math/big` which is not constant-time

**Files:** `internal/crypto/hash_to_curve.go`, lines 1–341  
**File:** `internal/crypto/crypto.go`, lines 125–137

The SSWU hash-to-curve implementation (RFC 9380) uses Go's `math/big` package for all field arithmetic. The comment on line 4–7 of `hash_to_curve.go` states:

> "All field arithmetic uses math/big, which is not instruction-level constant-time, but the algorithm has NO data-dependent conditional branches on secret inputs — the same code path executes for every input."

This is partially correct — the algorithm structure has no branches on secret data. However, `math/big` internally:

- Allocates memory based on value size
- Uses variable-time algorithms for modular exponentiation (used in `inv()` and `sqrtRatioP256`)
- The `sgn0()` function in `mapToCurveSSWU` (line 193–195) extracts the LSB with `big.Int.And()` — this is data-dependent.

The password goes into the DST which is fed into SHA-256 before SSWU, so direct password extraction is not straightforward. However, a close-proximity attacker with fine-grained timing measurements could potentially learn information about the password.

**Risk:** Theoretical timing side-channel on the CPace password.

**Recommendation:** Replace `math/big` with a constant-time field arithmetic library (e.g., cloudflare/circl or filippo.io/nistec which is already an indirect dependency). Alternatively, accept this as a documented limitation since CPace uses the password only to derive a generator point (not as a direct private key).

---

#### 4. Channel existence is disclosed via error messages

**File:** `internal/server/server.go`, lines 266–271

```go
if !s.store.ChannelExists(channelID) {
    writeError(conn, "channel not found")
    return
}
```

A client learns whether a specific 16-bit channel ID exists by trying to join it. This is intentional (protocol design) but combined with the small ID space (65535), an attacker can enumerate active channels with ~65536 probes.

**Mitigation:** Rate limiting (5 req/s, burst 15) limits enumeration to ~15 channels per burst, then 5/second. At this rate, enumerating the full space takes ~3.6 hours. Consider returning a generic "operation failed" for all join errors on non-existent or already-joined channels.

**Status: Fixed.** A dedicated `joinRL` rate limiter is applied to `handleJoin` before any channel lookup, and all join failures (non-existent channel, duplicate receiver) return the generic error `"operation failed"`. Per-endpoint rate limiters prevent cross-endpoint starvation (see #6).

---

### P2 — Fix when possible

#### 5. Small channel ID space (16-bit)

**File:** `internal/crypto/crypto.go`, lines 670–674

Channel IDs are random `uint16` values (65535 possible). This limits the anonymity set for active channels. An attacker who observes a channel allocation knows there is a 1/65535 chance of collision with another active channel.

The small space also means that an active server with many concurrent channels could see collisions. With rate limiting at 5 alloc/s, at most ~18,000 channels could be active per hour.

**Risk:** Low in practice — collisions are unlikely at typical usage levels.

**Recommendation:** Document the limitation. The current design is acceptable for a tool focused on one-off transfers.

---

#### 6. Rate limiter covers all endpoints together, not per-operation

**File:** `internal/server/server.go`, lines 177–181 and 198–203  
**File:** `internal/server/ratelimit.go`

The single `RateLimiter` instance protects both `/cert` and `/ws`. An attacker who uses `/cert` requests consumes from the same token bucket as WebSocket operations. A burst of `/cert` requests (e.g., 15) could temporarily starve WebSocket connections.

**Recommendation:** Create separate rate limiters for `/cert` and WebSocket, or use a stricter per-endpoint configuration in production.

**Status: Fixed.** `Server` now holds `certRL`, `wsRL`, and `joinRL` — separate `RateLimiter` instances for the `/cert` endpoint, WebSocket upgrades, and join attempts. Each endpoint has its own token bucket, so `/cert` abuse no longer starves WebSocket connections. The `joinRL` instance also protects against channel enumeration (see #4).

---

#### 7. Rate limiter bucket map has no hard cap

**File:** `internal/server/ratelimit.go`, lines 133–142

`Cleanup()` removes buckets inactive for 30 minutes, called every 10 minutes. If an attacker sends requests from many distinct IPs (e.g., botnet), the bucket map could grow large before the next cleanup cycle. Each bucket entry is a `map[string]*bucket` (key ~64 bytes HMAC-hex, value ~32 bytes + overhead). At 10,000 unique IPs, this is roughly 1–2 MB — not critical, but unbounded.

**Recommendation:** Add a hard cap on the number of buckets (e.g., 100,000). When exceeded, evict the least-recently-seen bucket.

---

#### 8. Information disclosure through error message text in relay

**File:** `internal/server/server.go`, lines 384–388

```go
writeError(conn, "unexpected message type: channel terminated")
writeError(conn, "unexpected message type")
```

The server sends different error messages depending on whether the failure threshold has been reached. A client can infer the internal failure counter state.

**Recommendation:** Use the same error message text regardless of internal state to avoid leaking information.

---

### P3 — Note for next iteration

#### 9. UDP mux channels drop packets when full

**Files:** `internal/network/network.go`, lines 62–69

```go
select {
case m.probeCh <- udpDatagram{data: pkt, addr: addr}:
default:  // drop
}
```

Both `quicCh` (buffer 256) and `probeCh` (buffer 64) silently drop packets when full. Under heavy load or a DoS attack, legitimate QUIC packets are dropped. This affects reliability.

**Recommendation:** Consider using a blocking send or a larger buffer, and log dropped packets at debug level for observability.

---

#### 10. Server private key stored in same file as configuration

**File:** `internal/config/config.go`, lines 89–98  
**File:** `CONTEXT.md`, lines 31–32

The server's TLS private key is stored in `config.yaml` (permissions 0o600). This is an intentional design choice (H-04 in CONTEXT.md): a single config file avoids a separate keystore.

**Risk:** Any process or user with read access to the config file obtains the private key. In container environments, the key may be exposed through volume mounts or backups.

**Recommendation:** Document the operational guidance: use filesystem permissions, containers, or systemd `LoadCredential` for isolation.

---

#### 11. Metadata filename only protected by `filepath.Base` + second layer

**Files:** `internal/cli/rx.go`, lines 435–436  
**File:** `pkg/transfer/transfer.go`, lines 83–86

The receiver strips directory components from the sender-provided filename using `filepath.Base` and then `SafeDestinationPath` applies it again. This is correct but relies on Go's `filepath.Base` semantics. While no bypass is known, this is a defense-in-depth note: both layers use the same function, so a bug in `filepath.Base` would affect both.

**Recommendation:** No change needed — double protection is good. Note that this is correct as-is.

---

#### 12. Stale SQLite test names

**File:** `internal/server/server_test.go`, lines 195–276

Test functions `TestSQLiteStore`, `TestSQLiteStoreFetchMissing`, `TestSQLiteStoreRecordFailure`, `TestSQLiteStorePurgeExpired`, `TestSQLiteStoreDeleteChannel` exist but actually test `MemoryStore`. These are relics from when SQLite was removed. They test the same code paths as the `TestMemoryStore*` functions.

**Risk:** None. Code is correct, test names are misleading.

**Recommendation:** Rename to `TestMemoryStore*` or remove the duplicates.

---

## Positive Findings

The project has several well-implemented security controls worth highlighting:

| Control | Location | Notes |
|---------|----------|-------|
| WebSocket Origin check | `internal/server/server.go:94-96` | Blocks browser-based CSRF by rejecting non-empty Origin headers |
| Constant-time cert fingerprint comparison | `internal/network/network.go:326` | Uses `crypto/subtle.ConstantTimeCompare` |
| Per-channel blob and CPace failure limits | `internal/server/server.go:344-350, 413-426` | Prevents resource exhaustion per session |
| Salt rotation + HMAC-hashed IPs in rate limiter | `internal/server/ratelimit.go:88-101, 106-109` | Daily salt rotation, raw IPs never stored |
| TOCTOU prevention on duplicate receiver joins | `internal/server/server.go:274-297` | Lock held across check-and-insert |
| SHA-256 integrity stream after payload | `pkg/transfer/transfer.go:112-119` | Hash computed during transfer, verified after |
| AES-256-GCM with AAD for endpoint bundles | `internal/crypto/crypto.go:201-215` | Channel ID bound as AAD |
| SAS via TLS ExportKeyingMaterial | `internal/cli/tx.go:718-722` | Binds SAS to session-specific TLS state |
| Ephemeral P-256 certs for QUIC | `internal/cli/tx.go:523-548` | 24-hour validity, regenerated per transfer |
| SAS prompt reads from /dev/tty | `internal/cli/tx.go:586-591` | Won't read piped stdin content |

---

## Priority Order — What to Fix First

| Priority | Issue # | Summary | Effort |
|----------|---------|---------|--------|
| **1** | #1 | `hermod trust` has no TLS verification during fetch | Small (add VerifyPeerCertificate when --fingerprint is set) |
| **2** | #2 | `InsecureSkipVerify: true` always, even without pinning | Small (conditionally enable CA verification) |
| **3** | #3 | math/big in CPace hash-to-curve may leak timing | Large (replace field arithmetic library) |
| **4** | #4 | Error messages leak channel existence | Small (use generic error text) |
| **5** | #6 | Shared rate limiter for /cert and /ws | Small (separate rate limiters) |
| **6** | #7 | Rate limiter bucket map has no hard cap | Small (add bucket limit with LRU eviction) |
| **7** | #8 | Error text reveals internal failure count state | Small (use uniform error messages) |
| **8** | #9 | UDP mux channels drop packets when full | Medium (larger buffers, log drops) |
| **9** | #5 | Small 16-bit channel ID space | Accept (documented limitation) |
| **10** | #10–12 | Documentation and cleanup items | Small |

---

## Files Audited

| File | Lines | Key Areas |
|------|-------|-----------|
| `internal/server/server.go` | 445 | WebSocket relay, channel management, error handling |
| `internal/server/store.go` | 152 | In-memory signaling store |
| `internal/server/ratelimit.go` | 142 | Token bucket rate limiter with salt rotation |
| `internal/crypto/crypto.go` | 714 | CPace PAKE, AES-256-GCM, SAS, identicon, transfer codes |
| `internal/crypto/hash_to_curve.go` | 341 | RFC 9380 SSWU hash-to-curve for P-256 |
| `internal/network/network.go` | 337 | UDP mux, hole punching, QUIC dial/listen, cert pinning |
| `internal/network/signaling.go` | 265 | WebSocket signaling client, TLS config |
| `internal/network/handshake.go` | 156 | CPace msg + endpoint bundle encoding, local endpoint discovery |
| `internal/config/config.go` | 252 | YAML config, TLS config, cert generation |
| `internal/cli/tx.go` | 783 | Sender command flow |
| `internal/cli/rx.go` | 527 | Receiver command flow |
| `internal/cli/serve.go` | 155 | Server command flow |
| `internal/cli/trust.go` | 94 | Certificate pinning command |
| `internal/cli/server_trust.go` | 22 | Server trust enforcement |
| `internal/cli/cancel.go` | 44 | QUIC cancellation handling |
| `internal/cli/verbosity.go` | 105 | Logging configuration |
| `pkg/transfer/transfer.go` | 134 | Payload metadata, path safety, stream hashing |
| `cmd/hermod/main.go` | 14 | Entry point |

---

## Out of Scope

The following were reviewed but are outside the security audit's primary focus:
- CI/CD configuration (`.github/workflows/`)
- Build/release scripts (`scripts/`)
- E2E test scripts (`e2e/testdata/`)
- Changelog and version files
- Previous audit reports

---

*End of report. No code changes were made during this audit.*
