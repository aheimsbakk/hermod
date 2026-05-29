# Security Audit Report — Hermod Zero-Knowledge File Transfer

**Auditor:** Qwen 3.6 Plus (Vibe Agent)
**Date:** 2026-05-29
**Scope:** Full static analysis of cryptographic primitives, protocol design, transport security, server hardening, and zero-knowledge / zero-trust claims.
**Codebase:** Go (quic-go, gorilla/websocket, crypto/elliptic, crypto/aes)

---

## Executive Summary

Hermod implements a peer-to-peer file transfer system with a CPace-based PAKE handshake, AES-256-GCM encrypted signaling, ephemeral TLS certificate pinning over QUIC, and optional SAS verification. The architecture is sound and the zero-knowledge claim is **largely valid** — the signaling server never sees plaintext data. However, several **critical and high-severity findings** exist in the cryptographic implementation, protocol flow, and server hardening that undermine the zero-trust posture.

| Severity | Count |
|----------|-------|
| Critical | 3     |
| High     | 5     |
| Medium   | 6     |
| Low      | 4     |
| Info     | 3     |

---

## 1. Critical Findings

### C-1: CPace Implementation Is Not Constant-Time — Timing Side-Channel

**File:** `internal/crypto/crypto.go`, lines 91-123 (`cpaceGenerator`)
**Severity:** Critical

The hash-to-curve function uses a try-and-increment loop with `math/big.Int` operations (`Mul`, `Mod`, `Exp`, `Sub`). Go's `math/big` is **not constant-time**. The number of iterations and the time spent in each iteration leaks information about the password through timing side-channels. An attacker who can measure handshake timing across many attempts can narrow the password space.

**Impact:** Reduces effective entropy of the transfer code passphrase. A 3-word code (~36 bits of entropy from a 256-word list) could be further weakened.

**Remediation:**
- Use a constant-time hash-to-curve implementation (e.g., RFC 9380 / `crypto/internal/fips140` primitives).
- At minimum, add a fixed-time delay after each CPace attempt to mask timing variance.
- Consider switching to a vetted PAKE library (e.g., `github.com/cisco/go-tls13` OPAQUE or `filippo.io/kyber`).

### C-2: No Point Validation on Own Public Key — Small-Subgroup / Invalid-Curve Attack

**File:** `internal/crypto/crypto.go`, lines 38-61 (`CPaceInit`)
**Severity:** Critical

`CPaceInit` generates the ephemeral public key `Y = scalar * G_password` but **never validates that the computed point `(Yx, Yy)` is actually on the P-256 curve**. If `cpaceGenerator` returns a point that is on the curve but the scalar multiplication produces a point at infinity or an invalid result due to a bug, the public message sent to the peer could be malformed. More critically, `CPaceFinish` (line 76) performs `ScalarMult(peerX, peerY, s.scalar)` — if the peer sends a point not on the curve (which is checked), but the generator point itself is weak, the shared secret derivation could be compromised.

**Impact:** Could allow an active attacker to manipulate the shared secret if the generator point has low order.

**Remediation:**
- Validate the output point of `ScalarMult` in `CPaceInit` using `curve.IsOnCurve(Yx, Yy)`.
- Verify the generator point has full order (not the identity point).

### C-3: WebSocket `CheckOrigin` Accepts All Origins — CSRF / Cross-Site WebSocket Hijacking

**File:** `internal/server/server.go`, line 87
**Severity:** Critical

```go
upgrader: websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
},
```

The signaling server accepts WebSocket connections from **any origin**. A malicious website can open a WebSocket to the hermod signaling server and participate in or disrupt transfers.

**Impact:** Any website visited by a user with an active hermod server connection could hijack the WebSocket, send `allocate`/`join`/`blob` messages, and interfere with transfers.

**Remediation:**
- Restrict `CheckOrigin` to known trusted origins or reject the `Origin` header check entirely for non-browser clients (hermod uses a CLI, not a browser).
- Since hermod is a CLI tool, consider using a custom WebSocket subprotocol header and validating it.

---

## 2. High-Severity Findings

### H-1: Transfer Code Entropy Is Insufficient for Brute-Force Resistance

**File:** `internal/crypto/crypto.go`, lines 414-466
**Severity:** High

The default transfer code uses **3 words** from a 256-word list plus a 16-bit channel ID:
- Words: 256^3 = 2^24 ≈ 16.7 million combinations
- Channel ID: 2^16 = 65,536 possibilities
- Combined: ~2^40 bits of entropy

However, the **channel ID is transmitted in the clear** during `allocate`/`join` messages. An attacker who observes the channel ID only needs to brute-force the 3-word passphrase (2^24 ≈ 16.7M). With the server allowing 3 CPace failures before dropping, a single attacker gets only 3 guesses. But a **distributed attack** across many IPs (the rate limiter uses /32 for IPv4) could each get 3 attempts. With 5,592 IPs, an attacker could exhaust the entire space.

**Impact:** A coordinated attack with sufficient IP addresses could brute-force a 3-word transfer code.

**Remediation:**
- Increase the default word count to at least 4 (2^32 ≈ 4.3 billion).
- Implement server-side global rate limiting on CPace failures across all channels, not just per-channel.
- Add exponential backoff on the server side for repeated join attempts.

### H-2: Ephemeral Certificates Use RSA-2048 — Should Use Ed25519

**Files:** `internal/cli/tx.go` line 438, `internal/config/config.go` line 143
**Severity:** High

Both the client ephemeral certificates and the server certificate use **RSA-2048**. RSA-2048 is considered acceptable but is slower and larger than modern alternatives. More importantly, RSA key generation is significantly slower than Ed25519, increasing the time-to-connect.

**Impact:** Performance degradation and larger certificate fingerprints. Not a direct security break, but RSA-2048 will be deprecated by NIST by 2030.

**Remediation:**
- Switch to Ed25519 for ephemeral certificates: `ed25519.GenerateKey(rand.Reader)`.
- For the server certificate, consider ECDSA P-256 or Ed25519.

### H-3: No Replay Protection on CPace Messages

**File:** `internal/network/signaling.go`, `internal/server/server.go`
**Severity:** High

CPace messages are relayed through the server without any nonce, timestamp, or sequence number. An attacker who captures a CPace public message could replay it within the channel TTL (default 600 seconds). While CPace itself is resistant to replay (the shared secret depends on the password), a replayed message could cause a peer to derive a key with the wrong session state.

**Impact:** Session confusion if messages are replayed within the TTL window.

**Remediation:**
- Include a nonce or timestamp in the `CPaceMsg` struct.
- The server should reject duplicate blob messages for the same channel.

### H-4: Hole Punching Accepts First Response Without Peer Identity Verification

**File:** `internal/network/network.go`, lines 143-187 (`HolePunch`)
**Severity:** High

The hole punching mechanism accepts the **first UDP probe response** from any source and uses that as the peer address. There is no cryptographic binding between the probe response and the expected peer. An attacker on the network path could send a forged probe response and redirect the QUIC connection to a malicious endpoint.

**Impact:** Man-in-the-middle during NAT traversal. The QUIC certificate pinning would catch this **only if** the attacker cannot forge the peer's certificate. However, the connection attempt would fail, causing a denial of service.

**Remediation:**
- Include a cryptographic challenge in the probe packet (e.g., HMAC of the shared key `K_classical`).
- Verify the responding address matches one of the expected candidates from the encrypted endpoint bundle.

### H-5: Signaling Server Relays Blobs Without Size Limits Per Message

**File:** `internal/server/server.go`, line 19 (`maxMessageSize = 65536`)
**Severity:** High

While `maxMessageSize` is set to 64 KiB per WebSocket message, the server relays blobs without validating their content. An attacker could send 10 blobs of 64 KiB each (the blob limit), consuming 640 KiB of relay bandwidth per channel. With many channels, this could exhaust server memory.

**Impact:** Memory exhaustion on the signaling server through crafted blob messages.

**Remediation:**
- Enforce a total relayed bytes limit per channel (not just blob count).
- Add server-side memory limits for the `MemoryStore`.

---

## 3. Medium-Severity Findings

### M-1: SAS Derivation Uses `ExportKeyingMaterial` Without Context Binding

**File:** `internal/cli/tx.go`, line 567
**Severity:** Medium

```go
material, err := tlsState.ExportKeyingMaterial("hermod-sas-v1", nil, 32)
```

The `context` parameter to `ExportKeyingMaterial` is `nil`. This means the SAS is derived solely from the TLS session state without any additional binding to the transfer code, channel ID, or payload metadata. If two concurrent transfers happen between the same peers with the same TLS session (unlikely but possible with session resumption), the SAS would be identical.

**Impact:** SAS collision across sessions could confuse users during verification.

**Remediation:**
- Pass a non-nil context that includes the channel ID and transfer code: `ExportKeyingMaterial("hermod-sas-v1", []byte(channelIDBytes), 32)`.

### M-2: Config File Permissions Are Correct But Server Cert Is Stored in Plaintext

**File:** `internal/config/config.go`, lines 94, 163-168
**Severity:** Medium

The config file is written with `0o600` permissions (correct). However, the server's private key (`ServerKeyPEM`) is stored in plaintext in `config.yaml`. If the config directory is compromised, the server's TLS key is exposed.

**Impact:** Compromise of the server's TLS identity allows MITM attacks on all clients that have pinned the old fingerprint.

**Remediation:**
- Store the server key in a separate file with stricter permissions.
- Consider encrypting the key with a passphrase or using a hardware security module.

### M-3: No Certificate Revocation or Rotation Mechanism

**File:** `internal/config/config.go`, `internal/cli/trust.go`
**Severity:** Medium

Once a server certificate is pinned via `hermod trust`, there is no mechanism to revoke or rotate it. If the server key is compromised, all clients must manually re-run `hermod trust`.

**Impact:** Operational risk during key compromise events.

**Remediation:**
- Implement a key rotation protocol where the server can signal a new fingerprint.
- Support multiple pinned fingerprints per server with validity windows.

### M-4: `FetchServerFingerprint` Makes Two Connections — TOCTOU Race

**File:** `internal/network/signaling.go`, lines 203-239
**Severity:** Medium

`FetchServerFingerprint` opens a WebSocket connection with `InsecureSkipVerify: true`, closes it, then opens a second connection to extract the fingerprint. Between the two connections, the server's certificate could change (e.g., due to rotation or an active MITM).

**Impact:** The fingerprint returned may not match the certificate used in the subsequent actual connection.

**Remediation:**
- Extract the fingerprint from a single connection.
- Return both the fingerprint and the connection state atomically.

### M-5: `modSqrt` Double-Computes the Square Root

**File:** `internal/crypto/crypto.go`, lines 141-154
**Severity:** Medium

`modSqrt` calls `big.Int.ModSqrt` (which uses a constant-time algorithm in Go 1.23+) and then **also** computes the result manually using Euler's criterion. The first result is discarded. This is redundant and the manual computation is not constant-time.

**Impact:** Wasted CPU cycles and potential timing leakage from the non-constant-time Euler's criterion computation.

**Remediation:**
- Use only `big.Int.ModSqrt` and verify the result by squaring.
- Remove the manual Euler's criterion computation.

### M-6: `SafeDestinationPath` Has a TOCTOU Race on File Creation

**File:** `pkg/transfer/transfer.go`, lines 82-96
**Severity:** Medium

`SafeDestinationPath` checks if a file exists with `os.Stat`, then returns the candidate path. Between the check and the actual file creation, another process could create a file at that path, causing an overwrite or symlink attack.

**Impact:** Potential file overwrite or symlink exploitation on multi-user systems.

**Remediation:**
- Use `os.OpenFile` with `O_CREATE|O_EXCL` flags to atomically create the file.
- The caller (`saveToFile` in `rx.go`) already uses a temp file + rename pattern, which mitigates this, but `SafeDestinationPath` itself should be hardened.

---

## 4. Low-Severity Findings

### L-1: Duplicate Word in EFF Short Wordlist

**File:** `internal/crypto/crypto.go`, line 428
**Severity:** Low

The word `"emit"` appears twice in `effShortWordlist`. This slightly reduces entropy (255 unique words instead of 256).

**Remediation:** Remove the duplicate entry.

### L-2: `handleCert` Endpoint Is Non-Functional

**File:** `internal/server/server.go`, lines 145-155
**Severity:** Low

The `/cert` endpoint always returns an error or a placeholder message. It does not actually serve the server certificate. Clients use `FetchServerFingerprint` instead, which makes a separate TLS connection.

**Remediation:** Either implement the endpoint properly or remove it and update documentation.

### L-3: `password` Variable Is Redundantly Processed in `tx.go`

**File:** `internal/cli/tx.go`, lines 96-97
**Severity:** Low

```go
password := strings.SplitN(code, "-", 2)[1]
password = strings.ReplaceAll(password, "-", "-")
```

The `ReplaceAll` call is a no-op (replacing "-" with "-"). This is dead code.

**Remediation:** Remove the `ReplaceAll` line.

### L-4: No Rate Limiting on `RecvBlob` / `WaitReady` Timeout

**File:** `internal/network/signaling.go`
**Severity:** Low

`RecvBlob` and `WaitReady` loop indefinitely until a message arrives. There is no per-message timeout, only the context cancellation from the caller. A malicious server could hang the client indefinitely by not sending messages.

**Remediation:** Add a configurable timeout to `RecvBlob` and `WaitReady`.

---

## 5. Informational Findings

### I-1: Zero-Knowledge Claim Is Valid

The signaling server **never sees plaintext data**. All payloads are encrypted with AES-256-GCM using a key derived from CPace, which itself uses a password known only to the two peers. The server relays only encrypted blobs. This claim is correct.

### I-2: Zero-Trust Claim Is Partially Valid

The system implements several zero-trust principles:
- Certificate pinning for the signaling server (`hermod trust`)
- Ephemeral TLS certificates for QUIC with fingerprint pinning
- SAS verification for out-of-band identity confirmation
- No reliance on PKI or CAs

However, the system **trusts the signaling server** for:
- Correct relay of messages (no integrity verification of relayed blobs)
- Correct reporting of public IP addresses (STUN-like)
- Not colluding with an attacker to inject malicious blobs

The zero-trust claim is valid **only when SAS verification is enabled**. Without SAS, the system trusts that the peer who joined the channel is the intended recipient.

### I-3: QUIC Stream Ordering Is Correct

The protocol uses separate QUIC streams for SAS coordination, metadata, payload, and acknowledgment. The ordering and synchronization logic in `performSASCoordinated` is correct — both sides write before reading to avoid deadlock.

---

## 6. Zero-Knowledge / Zero-Trust Analysis

### What Works Well

| Component | Assessment |
|-----------|------------|
| CPace PAKE | Correct protocol choice. Password never transmitted. |
| AES-256-GCM | Authenticated encryption. Nonce is random. |
| Certificate pinning | Both server and peer certs are pinned. |
| Ephemeral certs | Generated per-session, never stored. |
| SAS verification | Out-of-band identity confirmation. |
| Payload integrity | SHA-256 verification on receive. |
| Server blind | Server sees only encrypted blobs. |
| Rate limiting | HMAC-hashed IP prefixes, daily salt rotation. |

### What Undermines Zero-Trust

| Component | Issue |
|-----------|-------|
| No SAS by default | `--verify` is opt-in. Without it, no peer identity verification. |
| Channel ID in clear | Enables targeted attacks on specific transfers. |
| Server as single point of failure | All signaling flows through one server. |
| No message authentication on relay | Server could inject or modify encrypted blobs (though decryption would fail). |
| Timing side-channel in CPace | Could leak password information. |

---

## 7. Recommendations by Priority

### Immediate (Before Production Use)

1. **Fix C-1:** Add constant-time guarantees or timing masks to CPace.
2. **Fix C-3:** Restrict WebSocket origin checking.
3. **Fix H-1:** Increase default word count to 4+ and add global rate limiting.
4. **Fix H-4:** Add cryptographic challenge to hole-punch probes.

### Short-Term

5. **Fix C-2:** Validate output points in `CPaceInit`.
6. **Fix H-2:** Switch to Ed25519 for ephemeral certificates.
7. **Fix H-3:** Add nonces to CPace messages.
8. **Fix H-5:** Add total byte limits per channel.
9. **Fix M-1:** Bind SAS derivation to channel context.

### Medium-Term

10. Fix M-2 through M-6.
11. Make SAS verification the default (opt-out rather than opt-in).
12. Add server-side blob deduplication and replay detection.
13. Implement certificate rotation protocol.

---

## 8. Conclusion

Hermod's architecture is fundamentally sound for a zero-knowledge file transfer system. The use of CPace PAKE, AES-256-GCM, ephemeral certificate pinning, and optional SAS verification demonstrates strong security thinking. However, the **timing side-channel in CPace**, **insufficient default passphrase entropy**, and **WebSocket origin acceptance** are critical issues that must be addressed before the system can be considered production-ready for security-sensitive use cases.

The zero-knowledge claim holds — the signaling server cannot decrypt transferred data. The zero-trust claim is conditional — it requires SAS verification to be enabled, which is currently opt-in. Making SAS verification the default would significantly strengthen the zero-trust posture.
