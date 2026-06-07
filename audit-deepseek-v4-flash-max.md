# Security Audit Report — Hermod P2P Transfer

**Audit date:** 2026-06-07
**Target:** `github.com/hermod/hermod` v0.10.2
**Scope:** All application source code (`cmd/`, `internal/`, `pkg/`)
**Model used for audit:** deepseek-v4-flash-max
**Previous audits consulted:** None (ignored per request)

---

## Severity Classification

| Level | Definition |
|-------|-----------|
| CRITICAL | Exploitable remotely, likely leads to data disclosure, integrity violation, or denial of service |
| HIGH    | Exploitable with some preconditions, or significant weakness in a security boundary |
| MEDIUM  | Best-practice violation, defence-in-depth weakness, or minor information leak |
| LOW     | Cosmetic, theoretical, or requires extreme preconditions |

---

## CRITICAL (1 finding)

### C-01: TOCTOU race condition in `handleJoin` allows two receivers to join the same channel

**File:** `internal/server/server.go` lines 269–297
**Status:** Fixed in v0.10.3

The channel has a one-receiver invariant that is enforced with a mutex-locked check:

```go
// lines 269-279: check
s.mu.Lock()
for _, w := range s.waiters[channelID] {
    if !w.sender {
        s.mu.Unlock()
        writeError(conn, "channel already has a receiver")
        return
    }
}
s.mu.Unlock()
```

The lock is **released** after the check. Then the receiver is added later under a fresh lock:

```go
// lines 287-297: add
s.mu.Lock()
s.waiters[channelID] = append(s.waiters[channelID], wsc)
```

Two concurrent `Join` requests for the same channel can both pass the check (neither sees a receiver) before either adds itself. Both become receivers on the same channel.

**Impact:**
1. Both receivers receive the same `MsgReady` signal.
2. Both receive forwarded blobs — the `relay` loop iterates `s.waiters[channelID]` and picks the first non-sender. Which receiver gets the blob is a race.
3. The `blobCount` counter increments independently for each relay loop, so the second receiver could exceed `maxBlobsPerChannel` on the sender's side synchronisation.
4. The legitimate receiver may have its connection displaced or starved.

**Recommendation:** Hold the mutex across the entire check-and-add window, or use a channel-level mutex/state machine instead of a shared waiter list.

---

## HIGH (4 findings)

### H-01: TLS certificate pinning hash comparison is vulnerable to timing side channels

**File:** `internal/network/network.go` line 246
**File:** `internal/network/signaling.go` line 53
**Status:** Fixed in v0.10.3

The fingerprint comparison uses Go string equality (`!=`), which short-circuits on the first differing byte:

```go
if got != expectedHex {
    return fmt.Errorf("cert fingerprint mismatch: got %s, want %s", got, expectedHex)
}
```

An attacker on the same LAN (or with sufficiently precise RTT measurements) could infer the correct fingerprint byte-by-byte by observing the timing difference between a first-byte match and a first-byte mismatch. While the comparison is over a network connection (adding noise), the reconnection overhead per attempt is small enough that a determined attacker with local network access could mount a timing attack.

**Impact:** In a scenario where an attacker can MITM the signaling connection and the user has not yet pinned the server certificate (TOFU), the attacker could brute-force a valid fingerprint to present a fraudulent certificate.

**Recommendation:** Use `crypto/subtle.ConstantTimeCompare` or `hmac.Equal` for the fingerprint comparison.

---

### H-02: `muxedConn` deadline methods are no-ops, risking resource starvation

**File:** `internal/network/network.go` lines 110–112
**Status:** Fixed in v0.10.3

```go
func (c *muxedConn) SetDeadline(t time.Time) error      { return nil }
func (c *muxedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *muxedConn) SetWriteDeadline(t time.Time) error { return nil }
```

The `muxedConn` wrapper discards all deadline requests silently. QUIC transport relies on context-based cancellation via `WithContext`, but no fallback deadline is set on the underlying `packetMux`. If a context is never cancelled (e.g., `context.Background()` is passed), `ReadFrom` on the `muxedConn` channel blocks indefinitely, pinning a goroutine in `readLoop`.

**Impact:** A slow or stalled peer can cause goroutine leaks and eventual resource exhaustion, leading to denial of service.

**Recommendation:** Implement deadlines in the mux by using `time.After` or a select on a timer alongside the channel read in `ReadFrom`.

---

### H-03: `Identicon` panics on short input — potential denial-of-service surface

**File:** `internal/crypto/crypto.go` line 352
**Status:** Fixed in v0.10.3

```go
if len(keyMaterial) < 16 {
    panic("identicon: need at least 16 bytes")
}
```

`panic` in library code aborts the process if the caller provides fewer than 16 bytes. Currently only called with SAS material (32 bytes), but this function has no access control — any future code path that calls `Identicon` with user-controlled short input would crash the entire process.

**Impact:** Denial of service if the call site changes or a new caller is added without sufficient validation.

**Recommendation:** Return an error instead of panicking, or document the contract more visibly and add a unit test that deliberately passes short input to confirm the panic pathway is caught.

---

### H-04: Server private key stored in YAML config file with ambient read risk

**File:** `internal/config/config.go` line 164–169
**Status:** Intentionally not fixed (v0.10.3). Single config file avoids a separate keystore with its own permissions. Key is ephemeral (regenerated if missing); file is 0o600. Documented in CONTEXT.md under Security Model.

The server's ECDSA P-256 private key is stored as PEM-in-YAML in `~/.config/hermod/config.yaml`:

```go
cfg.ServerKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
```

The file is created with permission `0o600` (owner read/write only). However:
- The key is stored in the **same file** as the configuration (not in a separate keystore).
- Any process running as the same user, or any backup/indexing tool that reads config files, can extract the private key.
- The YAML is not encrypted at rest.

**Impact:** Compromise of a user-level backup or file-read vulnerability exposes the server TLS private key, allowing an attacker to impersonate the signaling server (until the user rotates the key).

**Recommendation:** Consider a separate keystore file with stricter permissions (`0o400`), or derive the key from a password. At minimum, clearly document the risk.

---

## MEDIUM (7 findings)

### M-01: `padTo32` silently truncates oversized byte slices

**File:** `internal/crypto/crypto.go` lines 139–147

```go
func padTo32(n *big.Int) []byte {
    b := n.Bytes()
    if len(b) >= 32 {
        return b[:32]
    }
    ...
}
```

If `n.Bytes()` returns exactly 33 bytes (possible for P-256 field elements where the leading bit is set), the most significant byte is silently dropped. The truncation `b[:32]` discards the high byte. For P-256, coordinate values are modulo `p` (approximately 2^256 - 2^224 + ...), so `n.Bytes()` returns at most 32 bytes in practice. However, if the scalar multiplication output has any leading zero byte due to internal `big.Int` representation, this is harmless. The real concern is the lack of an explicit check — a future NIST curve with a different field size could silently produce wrong results.

**Impact:** Cryptographic integrity depends on this not being reached. Silent truncation is never acceptable in crypto code.

**Recommendation:** Add an explicit check: `if len(b) > 32 { panic or return error }`. Or use `big.Int.FillBytes(make([]byte, 32))` (Go 1.15+) which is guaranteed fixed-size.

**Fix status:** Fixed in v0.10.3. Replaced truncation with `FillBytes(make([]byte, 32))` which panics if the value exceeds 32 bytes (correct behavior for crypto code).

---

### M-02: Channel expiry not enforced on `StoreBlob` / `FetchBlob`

**File:** `internal/server/store.go` lines 70–97

`StoreBlob` and `FetchBlob` check only for channel existence in the map, not for expiry:

```go
func (m *MemoryStore) StoreBlob(id uint16, sender bool, blob []byte) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    ch, ok := m.channels[id]
    if !ok {
        return fmt.Errorf("channel %d not found", id)
    }
    ...
}
```

Expired channels remain in the map until `PurgeExpired` runs (every 60 seconds via `RunGC`). A client holding a stale WebSocket connection could store blobs on an expired channel.

**Impact:** Low — the relay loop is bounded by `maxBlobsPerChannel` and the server only forwards blobs to connected peers. But in principle, a blob could be stored and later fetched after the intended TTL.

**Recommendation:** Check `time.Now().After(ch.expires)` in both `StoreBlob` and `FetchBlob`.

**Fix status:** Fixed in v0.10.3. Both methods now reject operations on expired channels.

---

### M-03: `FetchServerFingerprint` opens a second WebSocket connection for cert extraction

**File:** `internal/network/signaling.go` lines 215–251

The function first opens a connection with `dialSignaling(serverURL, "")` (no verification), then discards it and opens a *second* connection with a custom `VerifyPeerCertificate` callback to capture the fingerprint:

```go
client, err := dialSignaling(serverURL, "")   // first connection
defer client.Close()

// ... second connection
conn2, _, err := dialer.Dial(wsURL, nil)
```

The first connection is wasteful and performs a TLS handshake with no verification at all (TOFU with extra steps). The fingerprint from the first connection is never extracted.

**Impact:** Inefficient and confusing — the first connection could be exploited by a MITM attacker who presents a fraudulent cert, though the fingerprint from the second connection would differ. The real risk is that the developer or future maintainer may not understand this and inadvertently rely on the first connection's result.

**Recommendation:** Remove the first connection entirely. The `/cert` endpoint (M-06 in the codebase) was added to solve this — use an HTTPS GET to `/cert` instead of a second WebSocket upgrade.

**Fix status:** Fixed in v0.10.3. `FetchServerFingerprint` now uses an HTTPS GET to the `/cert` endpoint instead of a double WebSocket connection.

---

### M-04: `rotateSaltIfNeeded` silently skips salt rotation on `rand.Read` failure

**File:** `internal/server/ratelimit.go` lines 90–94

```go
if _, err := rand.Read(newSalt); err != nil {
    return  // keep existing salt
}
```

If `crypto/rand` fails (extremely rare, but possible in resource-constrained environments like containers with depleted entropy), the salt is not rotated. The existing salt continues to be used indefinitely, and the HMAC keys for IP prefixes remain stable.

**Impact:** Reduced anonymity — IP prefix hashes remain the same across daily rotation boundaries, making it easier to correlate requests from the same IP across days.

**Recommendation:** Log the failure and retry on the next call, or fall back to a timer-based rotation with a warning.

**Fix status:** Fixed in v0.10.3. Failure is logged via `slog.Warn`; retry happens naturally on the next `Allow` call.

---

### M-05: `/cert` endpoint has no access controls

**File:** `internal/server/server.go` lines 176–185

```go
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
    ...
    _, _ = w.Write(s.certDER)
}
```

The endpoint serves the server's DER-encoded TLS certificate with no authentication, no rate limiting, and no CSRF protection. While serving a certificate is typically safe, it reveals:
- The exact certificate serial number and validity period (enumeration surface).
- Timing correlation with server restarts (if certs are regenerated).
- The endpoint is outside the WebSocket upgrade path and bypasses the WebSocket rate limiter.

**Impact:** Low — the cert is already public in the TLS handshake. But no rate limiting means an attacker could hammer this endpoint to cause CPU load on each request (TLS handshake, then cert serving).

**Recommendation:** Add rate limiting to the `/cert` endpoint, or serve it only over the established TLS connection.

**Fix status:** Fixed in v0.10.3. `handleCert` now uses the server's existing `RateLimiter` to enforce per-IP rate limits.

---

### M-06: Config directory falls back to `"."` silently on `UserHomeDir()` error

**File:** `internal/config/config.go` lines 58–63

```go
home, err := os.UserHomeDir()
if err != nil {
    return "."
}
```

If `os.UserHomeDir()` fails (possible in containers, minimal chroot jails, or misconfigured systems), the config directory silently falls back to the current working directory. This can cause:
- Config file creation in unexpected locations.
- The server private key to be written to a world-readable directory.
- Multiple instances of hermod in different directories to use different configs.

**Impact:** The server private key could end up in a directory with weak permissions.

**Recommendation:** Fall back to a well-known location with restricted permissions (e.g., `/tmp/hermod-<uid>`), or return an error so the user knows the config path is unreliable.

**Fix status:** Fixed in v0.10.3. Falls back to `/tmp/hermod-<uid>` instead of `"."`.

---

### M-07: Transfer code printed to stdout — risk of log capture

**File:** `internal/cli/tx.go` line 127

```go
fmt.Printf("Transfer code: %s\n", code)
```

The transfer code (the CPace PAKE password) is printed to stdout in plain text. If stdout is piped, redirected to a file, or captured by a logging system, the transfer passphrase is persisted.

**Impact:** Anyone with access to the sender's stdout log can decrypt the P2P session (assuming they also have access to the signaling relay).

**Recommendation:** Print to stderr (with `os.Stderr`) like all other user-facing status messages, or add a `--print-code` flag. Already the status message diverges from the `printStatus` / `log*` pattern used elsewhere.

**Fix status:** Fixed in v0.10.3. Uses `fmt.Fprintf(os.Stderr, ...)` instead of `fmt.Printf`.

---

## LOW (5 findings)

### L-01: Rate limiter cleanup buckets may grow between cycles

**File:** `internal/server/ratelimit.go` lines 130–138

Bucket cleanup runs every 10 minutes. Between cycles, a flood of distinct IPs can create arbitrarily many bucket entries (one per HMAC-hashed IP prefix). While each bucket is small (~88 bytes), an attacker with many IP addresses (IPv6 /64 subnet) could cause memory pressure.

**Impact:** Low — mitigated by the daily salt rotation which clears all buckets. An attacker with a large IPv6 botnet could cause temporary memory growth.

**Recommendation:** Acceptable risk. The daily rotation bounds the window.

---

### L-02: QUIC/probe channel buffers silently drop packets on overflow

**File:** `internal/network/network.go` lines 62–63, 66–68

```go
case m.probeCh <- udpDatagram{data: pkt, addr: addr}:
default:  // drop silently
```

When the channel buffer is full, UDP packets are silently dropped. For probe packets this is acceptable (retry mechanism in `HolePunch` retransmits every 200ms). For QUIC packets this degrades performance but QUIC has its own loss recovery.

**Impact:** Low — retransmission mechanisms handle drops. Under heavy load, performance degrades gracefully.

---

### L-03: SAS word selection has non-uniform bias

**File:** `internal/crypto/crypto.go` lines 316–323

```go
idx := int(keyMaterial[i]) % 256
if i%2 == 0 {
    words[i] = pgpWordListEven[idx%len(pgpWordListEven)]
} else {
    words[i] = pgpWordListOdd[idx%len(pgpWordListOdd)]
}
```

The word lists have lengths that may not evenly divide 256. The double modulo (`% 256` then `% len(list)`) introduces a slight bias toward earlier entries if `len(list)` does not divide 256. The SAS is for human verification, not cryptographic entropy, so this is acceptable.

**Impact:** Minimal — SAS entropy is reduced by a fraction of a bit.

---

### L-04: `dropChannel` has a small race window between read and delete

**File:** `internal/server/server.go` lines 392–402

```go
s.mu.Lock()
conns := s.waiters[channelID]
delete(s.waiters, channelID)
s.mu.Unlock()
// ... send errors, then:
_ = s.store.DeleteChannel(channelID)
```

Between releasing the mutex and calling `DeleteChannel`, a new channel with the same ID could be allocated. The `AllocateChannel` check (`channel %d already exists`) prevents double-allocation, but `DeleteChannel` would delete the new channel.

**Impact:** Low — the window is tiny and the channel ID is `uint16` (65536 possibilities). Exploitation requires precise timing.

---

### L-05: `SafeDestinationPath` may overwrite files after 9999 collisions

**File:** `pkg/transfer/transfer.go` lines 95–101

```go
for i := 1; i <= 9999; i++ {
    candidate = filepath.Join(dir, base+"("+strconv.Itoa(i)+")"+ext)
    if _, err := os.Stat(candidate); os.IsNotExist(err) {
        return candidate
    }
}
return candidate  // 9999th candidate, not re-checked
```

If all 9999 suffixed candidates already exist (extremely unlikely except in benchmark tests), the function returns the last candidate (`... (9999)`) without confirming it doesn't exist.

**Impact:** Very low — 9999 existing files with the same base name is a pathological edge case.

---

## Summary

| Severity | Count | Fixed | Status |
|----------|-------|-------|--------|
| CRITICAL | 1     | 1     | All fixed |
| HIGH     | 4     | 3     | 3 fixed, 1 documented (H-04) |
| MEDIUM   | 7     | 7     | All fixed |
| LOW      | 5     | 0     | Accepted risk (not in fix scope) |
| **Total** | **17** | **11** | |

**Fix status:** v0.10.3 — 11 findings fixed (C-01, H-01, H-02, H-03, M-01 through M-07). H-04 documented as intended behavior. Low findings accepted as-is.

**Overall assessment:** The codebase is well-structured and demonstrates thoughtful security design (CPace PAKE, TLS pinning, SAS verification, rate limiting). The CRITICAL and HIGH findings are concentrated in two areas: concurrency safety in the signaling server's channel management, and the robustness of the cryptographic/network glue code. All actionable findings from this audit have been addressed in v0.10.3.
