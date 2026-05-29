# Hermod Security Audit Report

**Auditor:** GLM-5.1  
**Date:** 2026-05-29  
**Scope:** Full codebase — crypto logic, signaling server, network layer, config, CLI, protocol flow  
**Version:** 0.7.0  

---

## Executive Summary

Hermod is a peer-to-peer file/text transfer tool that uses CPace PAKE over a trusted-signaling channel, followed by QUIC/TLS 1.3 with ephemeral certificate pinning. The architecture is well-designed for a zero-knowledge file transfer system: the signaling server never sees plaintext payload data, and the PAKE + certificate fingerprint commitment provides strong protection against man-in-the-middle attacks on the signaling channel.

The audit identifies **2 critical**, **3 high**, **6 medium**, and **5 low** severity findings. The most serious issues are (1) the CPace implementation deviates from RFC 9496 in a way that eliminates domain separation between sender and receiver, and (2) a TOCTOU race in the signaling server that allows blob injection between channels.

---

## 1. Cryptography

### 1.1 CRITICAL — CPace lacks proper domain separation (sender/receiver role)

**File:** `internal/crypto/crypto.go:38-62`  
**Function:** `CPaceInit(password, channelID, role string)`

The `role` parameter is accepted but **never used** in the generator derivation. The hash-to-curve input is:

```
"hermod-cpace-v1:{password}:{channelID}:"
```

Both sender and receiver using the same `password` and `channelID` produce **identical** generator points. This means a generated point `Y = y * G(password, channelID)` is valid on either side. While this does not break the key-agreement property (both sides still derive the same shared key), it violates RFC 9496 §6.2 which requires unique generator points per side ("sid" and "CI" — context information) to prevent certain algebraic attacks in multi-user or multi-session settings.

**Risk:** In theory, the lack of context separation could allow a party to replay its own message in the opposite role (reflection attack) or allow cross-session algebraic exploits. The practical risk for a single-session PAKE like Hermod is moderate, but it is a deviation from the spec that weakens the security proof.

**Recommendation:** Include the role in the hash-to-curve input:

```go
base := fmt.Sprintf("hermod-cpace-v1:%s:%d:%s:", password, channelID, role)
```

### 1.2 CRITICAL — CPace ISK derivation omits peer identity, making K susceptible to reflection attacks

**File:** `internal/crypto/crypto.go:66-81`  
**Function:** `CPaceSession.CPaceFinish(peerPub []byte)`

The shared secret is derived as:

```go
iskX, _ := curve.ScalarMult(peerX, peerY, s.scalar)
h := sha256.Sum256(padTo32(iskX))
k := h[:]
```

RFC 9496 §5.2 specifies that the ISK (Intermediate Shared Key) must derive from hashing **both** public messages and the generator, not just the x-coordinate of the scalar multiplication. The current implementation hashes only `iskX`, which is the x-coordinate of `scalar * peerPub`. This means:

- If an attacker reflects the sender's own public message back, the computation `scalar * ownPub` yields a different point, but the x-coordinate of this point could leak information about the scalar.
- The key is not bound to the specific generator point, the channel ID, or the role — so the same password on different channels or roles produces keys that are algebraically related.

**Risk:** The shared secret is not bound to transcript data. Two sessions with the same password could produce related keys, and a man-in-the-middle who controls the signaling relay can perform endpoint substitution if the SAS check is skipped.

**Recommendation:** Derive the final key by hashing a full transcript as specified in RFC 9496:

```go
// ISK = H(sid || G || Y_a || Y_b || isk_x)
transcript := append(append(append(append([]byte(sid), gBytes...), yaBytes...), ybBytes...), padTo32(iskX)...)
k := sha256.Sum256(transcript)
```

At minimum, include `channelID`, `role`, and both `pubMsg` values in the hash input.

### 1.3 MEDIUM — Try-and-increment hash-to-curve is not constant-time

**File:** `internal/crypto/crypto.go:91-123`  
**Function:** `cpaceGenerator(password, channelID uint16)`

The try-and-increment loop iterates until it finds a valid curve point. The number of iterations varies based on the input, which creates a timing side channel: an attacker observing cycle counts can distinguish between different passwords or channel IDs. RFC 9496 recommends using a constant-time hash-to-curve method (e.g., SSWU, simplified SWU, or Elligator).

**Risk:** Low practical exploitability over WebSocket (timing granularity is too coarse), but it violates the security proof's constant-time assumption.

**Recommendation:** Replace try-and-increment with a constant-time hash-to-curve method such as the Simplified SWU method specified in RFC 9383, or use Go's `crypto/ecdh` P-256 library which provides constant-time operations. Given that this is a relatively low-traffic endpoint (once per transfer), the risk is reduced but should be addressed in a future hardening pass.

### 1.4 MEDIUM — AES-256-GCM Seal does not accept associated data (AAD)

**File:** `internal/crypto/crypto.go:209-224`  
**Function:** `Seal(key, plaintext []byte)`

The GCM seal operation is called with `nil` for associated data:

```go
ct := gcm.Seal(nonce, nonce, plaintext, nil)
```

The endpoint bundles exchanged over the signaling channel contain a `cert_fingerprint` and `require_verify` flag that should be integrity-protected. Without AAD, a malicious signaling server could potentially alter the encrypted blob's context (e.g., substituting a different channel's encrypted bundle) without detection, provided the nonce happens to be valid.

**Risk:** Moderate. The signaling server is untrusted by design. If the server substitutes an encrypted bundle from a different session (replay within the same channel), the nonce uniqueness would likely catch it, but binding the ciphertext to channel metadata via AAD would eliminate this class of attack.

**Recommendation:** Include the channel ID and message sequence number as AAD:

```go
aad := []byte(fmt.Sprintf("hermod-bundle-v1:%d:%s", channelID, role))
ct := gcm.Seal(nonce, nonce, plaintext, aad)
```

### 1.5 LOW — CPace scalar reduction uses modular reduction instead of rejection sampling

**File:** `internal/crypto/crypto.go:187-200`  
**Function:** `randScalar(n *big.Int)`

The implementation uses `k.Mod(k, n-1) + 1` which produces a slight bias toward lower values. For P-256 (n ≈ 2^256), the bias is negligible (less than 2^-128), so this is acceptable in practice.

**Risk:** Negligible.

**Recommendation:** No action required for P-256. If additional curves are added in the future, switch to rejection sampling.

### 1.6 LOW — Transfer code entropy is limited by wordlist size

**File:** `internal/crypto/crypto.go:443-466`  
**Function:** `GenerateTransferCode(numWords int)`

The channel ID has 16 bits of entropy (uint16) and each word is derived from a single byte (`int(b) % len(effShortWordlist)`). With the default 3 words over a 330-word list, the password entropy is approximately `log2(330^3) ≈ 25.7` bits, which is low for PAKE resistance against offline dictionary attacks. The channel ID adds 16 bits for a total of ~41.7 bits.

**Risk:** Low for the intended use case (short-lived transfers). An offline attacker who captures the signaling exchange would need ~2^26 guesses for the password portion, which is feasible with modest resources. However, the PAKE property ensures the attacker must interact with the honest party, not just compute offline.

**Recommendation:** Document that `--words 5` or higher is recommended for transfers where the code may be observed. The default 3-word code provides ~26 bits of password entropy, which is acceptable for a short-lived transfer code that is transmitted verbally. Consider adding a `--words` recommendation to the help text when `--verify` is not used.

### 1.7 LOW — SAS word list indices use modulo with small input range

**File:** `internal/crypto/crypto.go:314-325`  
**Function:** `SASFromBytes(keyMaterial []byte)`

The SAS uses only the first 8 bytes of 32-byte key material, and each word index is `keyMaterial[i] % len(wordlist)`. With wordlist sizes of ~180 and ~160 words, each byte provides ~7.2 and ~7.3 bits respectively. The total SAS entropy is approximately `4 × 7.2 + 4 × 7.3 ≈ 58` bits.

**Risk:** 58 bits is adequate for human verification. The real security comes from TLS Export Keying Material binding, which the SAS confirms.

**Recommendation:** No action required.

---

## 2. Signaling Server

### 2.1 HIGH — Race condition: blob forwarding without persistent peer mapping

**File:** `internal/server/server.go:249-333`  
**Functions:** `relay()`, `handleAllocate()`, `handleJoin()`

The `relay()` function iterates over `s.waiters[channelID]` to find the peer and forwards the blob inline:

```go
s.mu.Lock()
for _, w := range s.waiters[channelID] {
    if w.sender != isSender {
        w.conn.WriteJSON(Message{...})
        forwarded = true
        break
    }
}
s.mu.Unlock()
```

While the lock is held during iteration, the following race exists: between the time a peer sends a `blob` and the time the server forwards it, the intended recipient may have disconnected. The `WriteJSON` call under the mutex can block if the WebSocket write buffer is full, holding the server-wide mutex and blocking all other channel operations.

**Risk:** High. A slow or malicious peer can hold the server lock, causing a denial-of-service for all channels. Additionally, `WriteJSON` can return an error (e.g., connection closed) that is silently ignored — the blob is "forwarded" but never received.

**Recommendation:**
1. Move `WriteJSON` calls outside the mutex, using a per-connection write channel.
2. After unlocking, check if the write succeeded and inform the sender.
3. Add a write deadline to WebSocket connections: `conn.SetWriteDeadline(...)`.

### 2.2 MEDIUM — No message size enforcement on blob payloads

**File:** `internal/server/server.go:19`  
**Constant:** `maxMessageSize = 65536`

The `ReadLimit` is set to 64 KiB, but there is no per-blob size check. A client can send a 64 KiB blob, and the server will relay it. Since the endpoint bundle (encrypted with AES-256-GCM) plus overhead is typically < 1 KiB, the legitimate maximum blob size needed for the CPace exchange is a single P-256 point (65 bytes JSON-encoded ≈ 100 bytes). The endpoint bundle is also small (< 500 bytes encrypted).

**Risk:** Medium. The server will relay up to 10 × 64 KiB = 640 KiB per channel. An attacker can use this for traffic amplification or to exhaust server memory.

**Recommendation:** Reduce `maxMessageSize` to a reasonable maximum for CPace messages + encrypted endpoint bundles (e.g., 4096 bytes), or add a per-blob size check in `relay()`.

### 2.3 MEDIUM — No authentication on channel join

**File:** `internal/server/server.go:225-246`  
**Function:** `handleJoin()`

Any client that knows the channel ID can join a channel. The channel ID is a 16-bit integer included in the transfer code, so it is not secret. There is no mechanism to prevent an unauthorized client from joining and receiving or sending blobs.

**Risk:** Medium. An attacker who observes or guesses the channel ID can join and receive the CPace public message, then send their own CPace message. This would cause the honest peer to derive a different key, aborting the transfer (no data leak), but it does enable denial-of-service.

**Recommendation:** The CPace PAKE inherently protects against data leakage here — the attacker cannot derive the correct key without the password. However, the server should at minimum validate that a `join` is only accepted for channels that have been allocated and not yet joined. Currently this validation is missing; `handleJoin` will add a second receiver to the channel without checking.

### 2.4 MEDIUM — StoreBlob silently overwrites previous blobs

**File:** `internal/server/store.go:58-70`  
**Function:** `(m *MemoryStore) StoreBlob(id uint16, sender bool, blob []byte)`

Calling `StoreBlob` on the same channel/side multiple times silently overwrites the previous blob. A malicious client can replace a previously stored CPace message or endpoint bundle.

**Risk:** Medium. In the current relay model, blobs are forwarded immediately and not retrieved later, so overwriting has no effect on the protocol. However, if the store is used for asynchronous retrieval in the future, this would be exploitable.

**Recommendation:** Add a check: if a blob already exists for the given channel/side, return an error. This prevents replay within a channel.

### 2.5 LOW — Rate limiter only applies at WebSocket upgrade

**File:** `internal/server/server.go:158-167`  
**Function:** `handleWS()`

The rate limiter only checks `Allow()` once, at the point of WebSocket upgrade. After the connection is established, a client can send unlimited messages through the relay loop. This means a persistent connection can bypass rate limits.

**Risk:** Low in practice (the 10-blob limit per channel bounds the abuse), but the rate limiter does not protect against many simultaneous connection attempts.

**Recommendation:** No action required given the per-channel blob limit. If connection flooding becomes a concern, add a global concurrent-connection limit.

---

## 3. Network Layer

### 3.1 HIGH — Hole punching probe has no authentication

**File:** `internal/network/network.go:142-187`  
**Function:** `HolePunch()`

The probe/ack protocol uses fixed, predictable bytes:

```go
probe := []byte{probeMarker, 0xAB}
ack   := []byte{probeMarker, 0xCD}
```

Anyone who knows or guesses the UDP port can send a valid `ack` response, causing the peer to accept a connection from an attacker. The actual security comes from the QUIC certificate fingerprint pinning that follows, so the probe itself is not the final trust decision. However, a malicious party on the same LAN can answer probes faster than the legitimate peer, causing the QUIC connection to be established with them instead. The certificate pinning will then block the connection because the attacker's cert won't match.

**Risk:** High (denial of service). An attacker on the LAN can answer probe packets, causing the hole punch to "succeed" with the wrong address. The QUIC certificate mismatch will then cause the transfer to fail. The user sees a cryptic "cert fingerprint mismatch" error instead of a successful transfer.

**Recommendation:** Bind the probe/ack to the channel ID or a nonce derived from the CPace shared key:

```go
nonce := sha256.Sum256(append(kClassical, []byte("hermod-probe-v1")...))
probe = append([]byte{probeMarker}, nonce[:8]...)
```

This ensures only a party that completed the PAKE can produce a valid probe response, preventing LAN-based DoS.

### 3.2 MEDIUM — PacketMux silently drops packets when channels are full

**File:** `internal/network/network.go:50-71`  
**Function:** `packetMux.readLoop()`

When the `quicCh` (capacity 256) or `probeCh` (capacity 64) are full, incoming packets are silently dropped:

```go
default:
    // packet dropped — channel full
```

Under high traffic or a denial-of-service burst, this can cause legitimate packets to be lost, leading to QUIC connection timeouts or hole punch failures.

**Risk:** Medium. The channel sizes are reasonable for typical traffic, but a burst of spoofed UDP packets could fill both channels and cause a DoS.

**Recommendation:** Add metrics or logging for dropped packets (at debug level). Consider using a larger buffer or back-pressure mechanism for the QUIC channel.

### 3.3 LOW — Signaling TLS connection uses InsecureSkipVerify when no fingerprint is pinned

**File:** `internal/network/signaling.go:41-55`  

```go
tlsCfg := &tls.Config{
    InsecureSkipVerify: true,
}
```

When `pinnedFingerprint` is empty (during the `trust` command), the TLS connection accepts any certificate. This is by design — the `trust` command is used to fetch and pin the fingerprint — but it means the initial trust-on-first-use connection is vulnerable to a man-in-the-middle.

**Risk:** Low. This is inherent to trust-on-first-use models. The user is explicitly choosing to trust a server at this point. The fingerprint is then stored and verified on all subsequent connections.

**Recommendation:** Document this clearly in user-facing output. The current `hermod trust` command already prints the fingerprint. Consider adding a visual warning that the connection is unauthenticated during the initial trust step.

---

## 4. Configuration and Secrets

### 4.1 HIGH — Private key stored in plaintext in config.yaml

**File:** `internal/config/config.go:38,86-95,168`  
**Fields:** `ServerKeyPEM`, config file at `~/.config/hermod/config.yaml`

When `hermod serve` generates a self-signed server certificate, the private key is stored in plaintext in the config file:

```yaml
server_key_pem: "-----BEGIN PRIVATE KEY-----\n..."
```

The config file is created with mode `0o600` (owner read/write only), which is reasonable, but the private key is still stored unencrypted on disk. Any process running as the same user or root can read it.

**Risk:** High for the server certificate. If the server machine is compromised, the attacker can impersonate the signaling server and perform MitM attacks on future connections. However, since clients pin the certificate fingerprint via `hermod trust`, the attacker would also need to compromise the stored fingerprint in each client's config — a higher bar.

**Recommendation:** Separate the server private key from the general config file. Store it in a dedicated file (`~/.config/hermod/server-key.pem`) with `0o600` permissions and reference it by path. Better yet, support hardware-backed keys or at minimum prompt for a passphrase to encrypt the key at rest.

### 4.2 MEDIUM — Config file contains trusted server fingerprints, enabling targeted attacks on the config

**File:** `internal/config/config.go:36`  
**Field:** `TrustedServers map[string]string`

The `trusted_servers` map stores server URLs with their pinned certificate fingerprints. An attacker who can write to the config file could change a trusted server URL to point to a malicious server and update the fingerprint to match the attacker's certificate.

**Risk:** Medium. The attack requires local access to modify the config file, but there is no integrity protection (e.g., HMAC, signature) on the config itself.

**Recommendation:** Consider adding a config integrity check. At minimum, warn the user if the config file's modification time has changed since last use. A more robust solution would be to store fingerprints in a system keychain.

### 4.3 LOW — Transfer code is printed to stdout, which may be piped

**File:** `internal/cli/tx.go:100`  

```go
fmt.Printf("Transfer code: %s\n", code)
```

The transfer code (which serves as the PAKE password) is printed to stdout. If the user pipes the output (`hermod tx file.txt | ...`), the code could be captured by the downstream process or logged by systems that record stdout.

**Risk:** Low. The code is meant to be shared with the receiver. Printing it to stdout is the expected behavior.

**Recommendation:** Print the transfer code to stderr (alongside other status messages) instead of stdout. This ensures it is never accidentally captured by pipes.

---

## 5. Protocol Flow

### 5.1 MEDIUM — SAS verification protocol allows unilateral downgrade attack

**File:** `internal/cli/tx.go:244-247`  

The `require_verify` field is sent **inside** the encrypted endpoint bundle, which is encrypted with the PAKE-derived key. This means the authenticity of the field depends on the integrity of the CPace exchange. An attacker who controls the signaling server (can modify/replay blobs) could potentially substitute a bundle with `require_verify: false` for the legitimate one.

However, this is mitigated by the fact that the attacker cannot produce a valid AES-GCM ciphertext without knowing the PAKE key (which requires knowing the password). So if the password is secret, the bundle substitution fails.

**Risk:** Low. The signaling server cannot forge or modify encrypted bundles without breaking AES-256-GCM. This is noted for completeness.

**Recommendation:** No action required if AES-256-GCM is correctly implemented and the PAKE key is unknown to the attacker. Consider adding the `require_verify` flag as AAD in the AES-GCM seal (see finding 1.4).

### 5.2 MEDIUM — Metadata stream has no integrity protection beyond QUIC stream boundaries

**File:** `internal/cli/rx.go:280-289`  
**Function:** `readLenPrefixed()`

The metadata is transmitted as a length-prefixed JSON blob on a QUIC stream. QUIC provides stream-level integrity, so the metadata is protected in transit. However, there is no application-level signature or MAC on the metadata to protect against a malicious sender who sends a different `sha256` than the actual file content's hash.

**Risk:** Medium. A malicious sender could send `sha256: "0"` and a different payload, causing the receiver's integrity check to fail. This is a denial-of-service vector, not a data integrity compromise — the receiver will always verify the payload hash and reject mismatches.

**Recommendation:** No action required. The SHA-256 integrity check in `transfer.VerifyStream` catches this case. For completeness, the sender could sign the metadata with the PAKE-derived key, but this adds complexity without meaningful security benefit since the payload hash verification already protects the receiver.

### 5.3 LOW — No limit on QUIC stream count from sender

The sender opens streams sequentially (SAS → metadata → payload → ack). There is no mechanism to prevent a malicious sender from opening streams beyond the expected four. QUIC allows the receiver to limit the number of streams, but the default `quic.Config` does not set `MaxIncomingStreams`.

**Risk:** Low. A malicious sender can increase memory pressure on the receiver by opening many streams, but QUIC flow control and the `MaxIdleTimeout` of 30 seconds naturally bound this.

**Recommendation:** Add `MaxIncomingStreams: 4` to the receiver's `quic.Config` to explicitly limit the number of streams.

---

## 6. Logging and Error Handling

### 6.1 LOW — Server log messages may leak IP addresses

**File:** `internal/server/server.go:211-213`  

```go
host, _, _ := net.SplitHostPort(remoteAddr)
payload, _ := json.Marshal(map[string]string{"public_ip": host})
conn.WriteJSON(Message{Type: MsgOK, ChannelID: channelID, Payload: payload})
s.logger.Info("Channel allocated", "channel_id", channelID, "sender_ip", host, "ttl", s.ttl)
```

The server logs IP addresses at `Info` level. By default, the logging level is `none`, so this does not leak in production. However, if `--verbose info` or higher is used, IPs are logged to stderr without hashing.

**Risk:** Low. The rate limiter correctly hashes IPs with HMAC-SHA256 for bucket keys. The log messages are the only place raw IPs appear, and only when verbose logging is enabled.

**Recommendation:** Hash IP addresses in log messages using the same HMAC-SHA256 approach used by the rate limiter. Alternatively, log only the hashed version at `info` level and the full IP at `debug` level.

---

## 7. Findings Summary

| # | Severity | Category | Short Description |
|---|----------|----------|-------------------|
| 1.1 | CRITICAL | Crypto | CPace omits role from domain separation (generator derivation) |
| 1.2 | CRITICAL | Crypto | CPace ISK derivation omits transcript — key not bound to public messages |
| 1.3 | MEDIUM | Crypto | Try-and-increment hash-to-curve is not constant-time |
| 1.4 | MEDIUM | Crypto | AES-256-GCM Seal does not use associated data (AAD) |
| 1.5 | LOW | Crypto | Scalar reduction bias is negligible for P-256 |
| 1.6 | LOW | Crypto | Transfer code entropy is limited (~26 bits for default 3 words) |
| 1.7 | LOW | Crypto | SAS uses only 8 of 32 key-material bytes |
| 2.1 | HIGH | Server | WriteJSON under global mutex — DoS via slow/malicious peer |
| 2.2 | MEDIUM | Server | No per-blob size enforcement beyond 64 KiB WebSocket limit |
| 2.3 | MEDIUM | Server | No authentication on channel join (channel ID is public) |
| 2.4 | MEDIUM | Server | StoreBlob silently overwrites previous blobs |
| 2.5 | LOW | Server | Rate limiter only applies at WebSocket upgrade |
| 3.1 | HIGH | Network | Hole-punching probes have no authentication (LAN DoS) |
| 3.2 | MEDIUM | Network | PacketMux silently drops packets when channels are full |
| 3.3 | LOW | Network | InsecureSkipVerify during initial trust step (TOFU by design) |
| 4.1 | HIGH | Config | Server private key stored in plaintext config.yaml |
| 4.2 | MEDIUM | Config | No integrity protection on config file (fingerprint substitution) |
| 4.3 | LOW | Config | Transfer code printed to stdout (pipe capture risk) |
| 5.1 | MEDIUM | Protocol | SAS verify flag is inside encrypted bundle (theoretically safe) |
| 5.2 | MEDIUM | Protocol | Metadata SHA-256 is unauthenticated but receiver always verifies |
| 5.3 | LOW | Protocol | No limit on QUIC stream count from sender |
| 6.1 | LOW | Logging | Verbose logging may leak IP addresses |

---

## 8. Prioritized Remediation Plan

### Must Fix (before production release)

1. **[1.1 + 1.2] CPace transcript and domain separation** — Include the `role` string in the hash-to-curve input and derive the final key from a full transcript hash (`H(sid || G || Y_a || Y_b || isk_x)`). This brings the implementation in line with RFC 9496 and eliminates reflection attacks. Estimated effort: ~1 day.

2. **[2.1] Move WebSocket writes outside global mutex** — Refactor `relay()` to use per-connection write channels. Release the server mutex before writing to a peer. Estimated effort: ~1 day.

### Should Fix (next release)

3. **[1.4] Add AAD to AES-256-GCM** — Bind encrypted bundles to channel ID and message sequence. Estimated effort: ~2 hours.

4. **[3.1] Authenticate probe packets with PAKE-derived key** — Use `H(K_classical || "hermod-probe-v1")` as the probe/ack nonce. Estimated effort: ~4 hours.

5. **[4.1] Store server private key in a separate file** — Move private keys out of config.yaml into a dedicated file with restricted permissions. Estimated effort: ~2 hours.

6. **[2.2] Add per-blob size limit** — Reject blobs larger than 2048 bytes in the relay. Estimated effort: ~1 hour.

### Consider (future hardening)

7. **[1.3]** Replace try-and-increment with constant-time hash-to-curve (RFC 9383).
8. **[3.2]** Add metrics for dropped packets and consider back-pressure.
9. **[5.3]** Set `MaxIncomingStreams: 4` on the receiver's QUIC config.
10. **[6.1]** Hash IPs in server log messages at info level.
11. **[4.2]** Add config file integrity checks (HMAC or system keychain).

---

## 9. Positive Security Observations

The following aspects of the design and implementation are well-executed:

1. **Zero-knowledge architecture:** The signaling server never sees plaintext payload data. All sensitive data (CPace messages, endpoint bundles) is encrypted with the PAKE-derived key before relay.

2. **TLS 1.3 with certificate pinning:** Direct QUIC connections use ephemeral self-signed certificates with fingerprint verification, preventing MitM even if the signaling server is compromised (as long as SAS is verified).

3. **PAKE-based key exchange:** Using CPace ensures the password is never transmitted, even in hashed form. The signaling server only sees the encrypted blobs.

4. **Rate limiter design:** IP addresses are hashed with HMAC-SHA256 using a daily-rotating salt. Raw IPs are never stored in memory beyond the request lifetime.

5. **Channel resource limits:** Per-channel blob limits (10) and CPace failure limits (3) prevent abuse of individual channels.

6. **Symmetric SAS enforcement:** If either party uses `--verify`, both are forced to verify, preventing a downgrade attack where one party skips verification.

7. **File integrity verification:** SHA-256 is verified on the receiver side via `VerifyStream`, with atomic write (temp file + rename) preventing partial-file artifacts.

8. **Cancellation propagation:** QUIC application error codes cleanly propagate cancellation between peers.

9. **Post-quantum preference:** X25519MLKEM768 is listed as the preferred key exchange curve, providing hybrid post-quantum security.

10. **Proper TLS configuration:** Minimum TLS version is 1.3, strong cipher suites only (AES-256-GCM-SHA384, CHACHA20-POLY1305-SHA256).