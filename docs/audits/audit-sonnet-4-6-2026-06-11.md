# Security Audit — Hermod v0.16.1

**Model:** github-copilot/claude-sonnet-4.6  
**Date:** 2026-06-11  
**Scope:** Full codebase — `internal/`, `pkg/`, `cmd/`, `go.mod`  
**Methodology:** Manual source review, static analysis (`go vet`), dependency audit

---

## Summary

| Severity | Count |
|----------|-------|
| High     | 0     |
| Medium   | 0     |
| Low      | 1     |
| Info     | 2     |

No critical findings. The core security architecture is sound: CPace PAKE over an untrusted relay, ephemeral cert pinning, AES-256-GCM endpoint bundle encryption, SHA-256 trailing integrity, TLS 1.3 minimum, and per-IP HMAC-keyed rate limiting all work correctly as designed. `govulncheck` could not complete a module-level scan due to a type-information issue with `golang.org/x/sys/unix`; no known CVEs were identified in the dependency set through manual review.

The findings below are implementation defects and defense-in-depth gaps, not architectural breaks.

**All 4 high-severity findings (H1–H4), all 5 medium-severity findings (M1–M5), and 5 of 6 low-severity findings (L1–L5) have been fixed and verified. L6 (SASFromBytes fallback modulo bias) excluded by design — the fallback path is unreachable with 32-byte input and the fix would be a breaking API change with zero practical benefit. Tests pass.**

---

## High

### ~~H1 — HTTP server has no timeouts (Slowloris DoS)~~ ✅ Solved

**File:** `internal/server/server.go:124–128`

```go
s.httpServer = &http.Server{
    Addr:      ln.Addr().String(),
    Handler:   mux,
    TLSConfig: tlsCfg,
}
```

`ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, and `IdleTimeout` are all unset. A client that connects and sends HTTP headers very slowly holds a connection open indefinitely. On a public-facing server, an attacker can exhaust the goroutine pool and block all new connections with a small number of slow TCP sockets (Slowloris).

**Fix:**

```go
s.httpServer = &http.Server{
    Addr:              ln.Addr().String(),
    Handler:           mux,
    TLSConfig:         tlsCfg,
    ReadHeaderTimeout: 10 * time.Second,
    ReadTimeout:       30 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       120 * time.Second,
}
```

---

### ~~H2 — Deprecated `crypto/elliptic` scalar multiplication with a secret scalar~~ ✅ Solved

**Files:** `internal/crypto/crypto.go:63, 90, 156, 162`

```go
curve := elliptic.P256()
Yx, Yy := curve.ScalarMult(gx, gy, scalar.Bytes()) // scalar is the secret CPace scalar
iskX, _ := curve.ScalarMult(peerX, peerY, s.scalar)
```

`crypto/elliptic` was deprecated in Go 1.20 with an explicit warning: its `ScalarMult` and `ScalarBaseMult` functions are not safe to use with private scalars because they are not guaranteed to be constant-time. The CPace session scalar is a secret value. A timing side-channel on `ScalarMult` can, in principle, leak the scalar to an attacker capable of making repeated timed observations.

The scalar is ephemeral (one per session), so the practical attack window is narrow. However, the Go documentation is unambiguous: this API must not be used with secret inputs.

**Fix:** Replaced all `elliptic.P256().ScalarMult()` calls with `crypto/ecdh.P256()`, which provides constant-time scalar multiplication as part of the standard library. The `crypto/elliptic` import was removed from production code.

- `CPaceInit`: creates a `ecdh.PrivateKey` from the ephemeral scalar and a `ecdh.PublicKey` from the hash-to-curve generator point, then calls `ECDH()` to get the x-coordinate of `scalar * G_password`. The y-coordinate is recovered from the curve equation (`y² = x³ - 3x + b mod p`, with `p ≡ 3 mod 4` giving `y = (y²)^((p+1)/4) mod p`).
- `CPaceFinish`: uses `ecdh.P256().NewPublicKey()` to parse and validate the peer's point (on-curve check), then `ecdh.PrivateKey.ECDH(peerKey)` to compute the shared x-coordinate directly.
- `unmarshalPoint` (dead code) replaced entirely by `ecdh`'s built-in point validation — removed.
- No new dependencies; `crypto/ecdh` is in the standard library since Go 1.20.

---

### ~~H3 — DST silently truncated for long passwords — not RFC 9380 compliant~~ ✅ Solved

**File:** `internal/crypto/hash_to_curve.go:336–338`

```go
if len(dst) > 255 {
    // Truncate to 255 bytes as required by RFC 9380.
    dst = dst[:255]
}
```

The comment is incorrect. RFC 9380 §3.1 does **not** allow truncation. For DSTs longer than 255 bytes, it requires encoding the hash of the DST:

> "If a protocol requires a domain separation tag of length b > 255, implementors MUST define a new encoding… the first 32 bytes of the SHA-256 hash of the domain separation tag."

The DST format is `"hermod-cpace-v1:" (16) + channelID (2) + ":" (1) + password`. The prefix is 19 bytes, leaving 236 bytes for the password before truncation. The default 3-word code is ~15 bytes, safe. With `--words 47` or more (each word ≈5 chars), the DST exceeds 255 bytes and is silently truncated. Two passwords that share the same first 236 bytes produce the identical CPace generator and thus the same shared key — a collision.

**Fix:** Implement the RFC 9380 §3.1 long-DST encoding:

```go
if len(dst) > 255 {
    h := sha256.New()
    h.Write([]byte("H2C-OVERSIZE-DST-"))
    h.Write(dst)
    dst = h.Sum(nil) // 32 bytes, always <= 255
}
```

---

### ~~H4 — `dropChannel` writes to WebSocket connections outside mutex — concurrent write race~~ ✅ Solved

**File:** `internal/server/server.go:479–490`

```go
func (s *Server) dropChannel(channelID uint16) {
    s.mu.Lock()
    conns := s.waiters[channelID]
    delete(s.waiters, channelID)
    s.mu.Unlock()           // lock released here

    for _, w := range conns {
        _ = w.conn.WriteJSON(...)   // write outside mutex
        w.conn.Close()
    }
}
```

`dropChannel` is called from the relay goroutine when the CPace failure limit is reached. At the same time, the peer's relay goroutine may be writing a blob forward to the same connection. Gorilla WebSocket panics on concurrent writes to the same connection, which crashes the server process.

The project's own memory entry (documented in `docs/memory/archive/2026-06-09-writejson-inside-mutex.md`) records exactly this hazard: "WriteJSON must happen inside s.mu to avoid concurrent writes." `dropChannel` violates this pattern.

**Fix:** Perform the writes while holding the lock, or add a per-connection write mutex.

```go
func (s *Server) dropChannel(channelID uint16) {
    s.mu.Lock()
    conns := s.waiters[channelID]
    delete(s.waiters, channelID)
    for _, w := range conns {
        _ = w.conn.WriteJSON(Message{Type: MsgError, Error: "channel terminated: CPace failure limit exceeded"})
    }
    s.mu.Unlock()

    for _, w := range conns {
        w.conn.Close()
    }
    _ = s.store.DeleteChannel(channelID)
}
```

---

## Medium

### ~~M1 — WebSocket dial has no timeout and ignores context~~ ✅ Solved

**File:** `internal/network/signaling.go:67–93`

```go
dialer := websocket.Dialer{
    TLSClientConfig: tlsCfg,
    // HandshakeTimeout not set — defaults to no timeout
}
conn, _, err := dialer.Dial(wsURL, nil)  // not DialContext — context not passed
```

Two problems:

1. No `HandshakeTimeout` is set on the dialer. A slow or unresponsive server can hold the goroutine in the dial call indefinitely.
2. `Dial` is used instead of `DialContext`. A SIGINT or context cancellation from the caller (e.g., `runTx`'s signal context) will not cancel an in-progress WebSocket handshake.

**Fix:**

```go
dialer := websocket.Dialer{
    TLSClientConfig:  tlsCfg,
    HandshakeTimeout: 15 * time.Second,
}
// Pass a context wrapping the caller's context with the timeout already set
conn, _, err := dialer.DialContext(ctx, wsURL, nil)
```

The function signature of `dialSignaling` should be updated to accept a `context.Context`.

---

### ~~M2 — `io.ReadAll` without size limit on certificate fetch~~ ✅ Solved

**File:** `internal/network/signaling.go:318`

```go
certPEM, err := io.ReadAll(resp.Body)
```

A malicious server can stream an arbitrarily large response. The 10-second client timeout limits *time*, not *bytes*. On a fast connection, a server could deliver hundreds of MB within 10 seconds, exhausting process memory. A valid PEM certificate is at most a few kilobytes.

**Fix:**

```go
certPEM, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
if err == nil && len(certPEM) == 8192 {
    err = fmt.Errorf("certificate response exceeds maximum size")
}
```

---

### ~~M3 — `DialContext` callbacks ignore the provided context~~ ✅ Solved

**File:** `internal/network/signaling.go:296–301`

```go
transport.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
    return net.Dial("tcp4", addr)  // ignores context — no cancellation
}
```

The `_` parameter discards the context. If the parent context is cancelled while waiting for a TCP connection to be established, the dial continues uninterrupted.

**Fix:**

```go
transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
    return (&net.Dialer{}).DialContext(ctx, "tcp4", addr)
}
```

Apply the same fix to the IPv6 counterpart at line 300.

---

### ~~M4 — Temp file created with world-readable default permissions~~ ✅ Solved

**File:** `internal/cli/rx.go:472`

```go
f, err := os.Create(tmpPath)
```

`os.Create` uses mode `0666` before umask (typically resulting in `0644`). On a shared machine, another user can read a partially-written transfer while the download is in progress. This is particularly sensitive when receiving credentials, keys, or personal data.

`os.Create` also silently truncates an existing file. If a previous crashed transfer left a `.hermod_tmp` file, it will be overwritten without warning, losing any partial progress indicator.

**Fix:**

```go
f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
if os.IsExist(err) {
    // Stale temp from a previous crashed transfer — remove and retry.
    os.Remove(tmpPath)
    f, err = os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
}
```

---

### ~~M5 — Plaintext `ws://` accepted without warning~~ ✅ Solved

**Files:** `internal/network/signaling.go:46–48`, `internal/cli/trust.go:45`

The signaling client accepts `ws://` URLs. When `ws://` is used, TLS is not negotiated, so:

- The signaling channel is unencrypted.
- Certificate pinning is irrelevant (no certificate).
- A network-level attacker can observe CPace public messages and perform an offline dictionary attack on the transfer code.
- A MITM attacker can replace CPace messages, deriving the same PAKE key as the victim and reading the endpoint bundle.

The trust command auto-prepends `wss://` by default, and `requireTrustedServer` forces a pinned fingerprint for tx/rx. However, a user who manually sets `HERMOD_SERVER=ws://...` or explicitly uses a `ws://` server URL will get no warning.

**Fix:** Reject `ws://` in `dialSignaling` unless an explicit `--insecure` flag is provided, or at minimum log a prominent warning:

```go
case "ws":
    s.logger.Warn("Using plaintext WebSocket (ws://) — connection is not encrypted and is vulnerable to interception")
```

---

## Low

### ~~L1 — KindText input logged at debug level~~ ✅ Solved

**File:** `internal/cli/tx.go:117`

```go
logDebug("payload classified", "kind", kind, "name", name, "input", input)
```

When `kind == KindText`, `input` is the literal text being transferred (e.g., a password, API key, or private message). At `--verbose debug`, this appears in stderr output in plain text.

**Fix:** Redact the value for KindText:

```go
loggedInput := input
if kind == transfer.KindText {
    loggedInput = "<redacted>"
}
logDebug("payload classified", "kind", kind, "name", name, "input", loggedInput)
```

---

### ~~L2 — Trailing hash stream allows 1 MiB allocation per read~~ ✅ Solved

**File:** `internal/cli/rx.go:537`

```go
if length > 1<<20 { // 1 MiB sanity limit for metadata
    return nil, fmt.Errorf("metadata too large: %d bytes", length)
}
```

`readLenPrefixed` is called for both the metadata stream and the trailing hash stream. The trailing hash is always exactly 64 hex bytes (SHA-256). A corrupt or malicious sender can send a length prefix of 1,048,575 and force a 1 MiB allocation before the mismatch is detected.

**Fix:** Apply separate, tighter limits per call site. For the trailing hash stream (line 367 in rx.go), use 256 bytes:

```go
trailingHashBytes, hashErr := readLenPrefixedMax(hashStream, 256)
```

---

### ~~L3 — Ephemeral QUIC cert has a 24-hour validity window~~ ✅ Solved

**File:** `internal/cli/tx.go:563–564`

```go
NotBefore: time.Now().Add(-time.Minute),
NotAfter:  time.Now().Add(24 * time.Hour),
```

Ephemeral certificates exist only for the duration of a single transfer session (typically seconds to minutes). A 24-hour `NotAfter` means a leaked private key (e.g., from a memory dump or core file) remains usable for up to 24 hours. A 1–2 hour window would reduce the exposure period significantly with no functional impact.

**Fix:** `NotAfter: time.Now().Add(2 * time.Hour)`

---

### ~~L4 — Windows config path controlled by `APPDATA` environment variable~~ ✅ Solved

**File:** `internal/config/config.go:56`

```go
return filepath.Join(os.Getenv("APPDATA"), "Hermod")
```

If `APPDATA` is empty or set to an attacker-controlled path, the config file (which contains the server private key PEM) is written to an unintended location. `os.UserConfigDir()` is the idiomatic API and handles the Windows case reliably, including when `APPDATA` is unset.

**Fix:**

```go
dir, err := os.UserConfigDir()
if err != nil {
    return fmt.Sprintf("%s\\Hermod", os.TempDir())
}
return filepath.Join(dir, "Hermod")
```

---

### ~~L5 — `writeError` silently discards write errors~~ ✅ Solved

**File:** `internal/server/server.go:543–545`

```go
func writeError(conn *websocket.Conn, msg string) {
    conn.WriteJSON(Message{Type: MsgError, Error: msg})
}
```

If the write fails (connection already closed, broken pipe), the error is silently dropped. The client never receives the error message. This does not affect security but masks connection problems during debugging and is inconsistent with the project's error-handling rules.

**Fix:**

```go
func writeError(conn *websocket.Conn, msg string) {
    if err := conn.WriteJSON(Message{Type: MsgError, Error: msg}); err != nil {
        slog.Debug("Failed to write error to client", "err", err)
    }
}
```

---

### L6 — `SASFromBytes` fallback path has modulo bias

**File:** `internal/crypto/crypto.go:262–268`

```go
if offset+1 >= len(keyMaterial) {
    // Fallback: should not happen with 32 bytes of key material.
    words[wordIdx] = effShortWordlist[int(keyMaterial[offset%len(keyMaterial)])%n]
    wordIdx++
    offset++
    continue
}
```

The fallback uses `byte % n` (256 values mod 1296), which has modulo bias — some words are ~1.07× more likely than others. The comment correctly notes this path is unreachable with 32 bytes of key material and 6 words (at most ~14 bytes consumed in expectation). However, the dead code path is misleading and could become a live bug if the function is called with shorter input in the future.

**Fix:** Remove the fallback and return an error when key material is exhausted:

```go
if offset+1 >= len(keyMaterial) {
    // This should never happen with ≥13 bytes of key material.
    return nil, fmt.Errorf("SASFromBytes: insufficient key material (%d bytes)", len(keyMaterial))
}
```

Change the function signature to `SASFromBytes(keyMaterial []byte) ([]string, error)` accordingly.

---

## Informational

### I1 — Hole-punch nonce skips byte at index 7

**File:** `internal/network/network.go:210–211`

```go
probe := []byte{probeMarker, probeNonce[0], ..., probeNonce[6]}  // uses [0:7]
ack   := []byte{probeMarker, probeNonce[8], ..., probeNonce[14]} // uses [8:15]
```

Byte 7 of `probeNonce` is unused. This is not a security issue — 7 bytes (56 bits) each for probe and ack is more than sufficient. The skip is inconsistent with the comment "nonce[0:7]" vs "nonce[8:15]" (which implies a gap at index 7). Consider documenting it explicitly or using contiguous ranges `[0:7]` / `[7:14]`.

---

### I2 — `ChannelExists` and receiver-uniqueness check are not atomic across the store boundary

**File:** `internal/server/server.go:311–330`

`ChannelExists` acquires `MemoryStore.mu`, returns, then the server acquires `Server.mu` to check for duplicate receivers. The two operations are not atomic. Between the `ChannelExists` call and the `Server.mu` lock, the channel could expire (TTL GC) and be reallocated. In practice this race window is negligible (sub-millisecond), but it is worth noting as a theoretical inconsistency.

No fix required; the existing behavior is safe given the short time window and the generic "operation failed" error response. Document the deliberate choice in a comment if desired.

---

## Positive observations

The following practices are notably well-implemented and worth preserving:

- **PAKE over untrusted relay:** CPace with P-256 and hash-to-curve (RFC 9380 SSWU) gives correct domain separation, role binding, and no modulo bias on the scalar. The approach is sound.
- **Certificate pinning:** Mandatory `requireTrustedServer` before tx/rx, with `crypto/subtle.ConstantTimeCompare` on all fingerprint checks.
- **Rate limiting:** HMAC-SHA256 keyed bucket keys with daily salt rotation prevent raw IP tracking. Per-channel blob and CPace failure caps bound relay abuse.
- **Path traversal guard:** `filepath.Base` applied at both `saveToFile` and `SafeDestinationPath`, with `received` fallback for empty/dotfile names.
- **AES-GCM nonce:** `io.ReadFull(rand.Reader, nonce)` — random nonce per encryption, no counter reuse risk.
- **SAS key material:** TLS `ExportKeyingMaterial` binds the SAS to the specific TLS session; channel ID as context prevents cross-session replay.
- **TOCTOU guard on receiver join:** The duplicate-receiver check and the waiter append happen inside a single `s.mu` lock, per the documented pattern.
- **Integrity:** SHA-256 computed in parallel during transfer via `TeeReader`; trailing hash stream prevents accept-before-verify.
- **Config file permissions:** `0o600` for `config.yaml`, `0o700` for the config directory.

---

*End of report.*
