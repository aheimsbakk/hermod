# Security Audit: Hermod v0.18.0

**Audit date:** 2026-06-12
**Project:** Hermod — secure P2P file/text transfer (Go 1.25)
**Scope:** Full source tree (`internal/`, `pkg/`, `cmd/`, scripts, config)
**Methodology:** Manual code review, architecture analysis, dependency review

**Revision history:**

| Date | Change |
|---|---|
| 2026-06-12 | Audit conducted against v0.18.0 |
| 2026-06-12 | Recommendation #3 (SAS logging) resolved — `[CLOSED]` |
| 2026-06-12 | Recommendation #4 (recovery docs) resolved — `[CLOSED]` |
| 2026-06-12 | Rate limiter tests hardened against race-detector slowdown — certRL and joinRL test burst rates lowered from 100/s to 0.001/s to prevent token bucket refill between consecutive requests under race detector overhead |
| 2026-06-12 | Recommendation #2 (per-IP channel cap) resolved — `[CLOSED]` |

---

## 1. Executive Summary

Hermod is a peer-to-peer file transfer tool with a central signaling server. The signaling server brokers connection setup via CPace PAKE and NAT traversal; payload data flows directly between peers over QUIC/TLS 1.3. The signaling server never sees payload plaintext.

**Overall assessment:** The codebase demonstrates strong security awareness. Cryptographic primitives are correctly implemented, constant-time comparisons are used for sensitive operations, input validation is thorough, and the attack surface is well-defined. No critical or high-severity vulnerabilities were found.

**Severity distribution:**
- Critical: 0
- High: 0
- Medium: 3
- Low: 4
- Informational: 5

---

## 2. Cryptographic Review

### 2.1 CPace PAKE (RFC 9496)

**Implementation:** Package `internal/crypto/`

| Component | Assessment |
|---|---|
| Curve | P-256 (NIST) — appropriate for PAKE |
| Hash-to-curve | P256_XMD:SHA-256_SSWU_RO_ (RFC 9380) — constant-time, single computation |
| Scalar generation | Rejection sampling on [1, n-1] — uniform, unbiased |
| ECDH | `crypto/ecdh.P256()` — constant-time stdlib |
| ISK derivation | SHA-256(iskX || pubSender || pubReceiver) — role-ordered transcript prevents cross-role attacks |
| Role binding | Roles "sender"/"receiver" bound into transcript (verified by `TestCPaceRoleSeparation`) |

**Findings:**
- The `math/big` package is used for field arithmetic in SSWU (hash-to-curve). While `math/big` is not instruction-level constant-time, the SSWU algorithm has **no data-dependent conditional branches on secret inputs** — the same code path executes for every input. This is acceptable.
- Domain separation tag (DST) encodes `hermod-cpace-v1:<channelID>:<password>`, ensuring generator uniqueness per session. DSTs > 255 bytes are hashed per RFC 9380 §3.1. **Correct.**

### 2.2 Hybrid KEM (X25519 + ML-KEM-768)

**Implementation:** Package `internal/crypto/`

| Component | Assessment |
|---|---|
| X25519 ECDH | `crypto/ecdh.X25519()` — stdlib, constant-time |
| ML-KEM-768 | `crypto/mlkem` (Go 1.25 stdlib) — FIPS 203 compliant |
| Key combiner | SHA-256(kClassical || ssX25519 || ssMLKEM) — split combiner |
| Security property | Security ≥ max(CPace, X25519, ML-KEM-768) — post-quantum safe |

**Findings:**
- The combiner is a split concatenation. Security is bounded below by the strongest component: if P-256 falls to quantum cryptanalysis, ML-KEM-768 still protects the bundle. **Correct design.**
- ML-KEM ciphertext (1088 bytes) and encapsulation key (1184 bytes) are fixed-size binary fields, parsed with length checks. **Correct.**

### 2.3 AES-256-GCM (Signaling Payload Encryption)

**Implementation:** `internal/crypto.SealAAD` / `internal/crypto.OpenAAD`

| Property | Assessment |
|---|---|
| Key size | 32 bytes (AES-256) — verified |
| Nonce | 12 bytes from `crypto/rand` — fresh per encryption |
| AAD | Channel ID (2-byte big-endian) — binds ciphertext to session |
| Tag | GCM provides authentication + integrity |

**Findings:**
- Nonces are generated from `crypto/rand`. GCM nonce reuse would be catastrophic, but `crypto/rand` makes accidental reuse effectively impossible. **Correct.**

### 2.4 Random Number Generation

**Implementation:** All randomization uses `crypto/rand.Reader`.

- CPace scalars: rejection sampling on `crypto/rand` output
- Transfer code words: rejection sampling on `crypto/rand` output
- Server cert keys: `crypto/ecdsa.GenerateKey` with `crypto/rand.Reader`
- Ephemeral cert keys: same
- Rate limiter salt: `crypto/rand.Read`
- UDP reflector HMAC keys: `crypto/rand.Read`
- Channel IDs: `crypto/rand.Read` (16-bit)

**No use of `math/rand` for security-sensitive purposes found.** All paths use the OS CSPRNG.

### 2.5 Short Authentication String (SAS)

**Implementation:** `internal/crypto.SASFromBytes`

| Property | Assessment |
|---|---|
| Key material source | TLS ExportKeyingMaterial("hermod-sas-v1", context, 32) |
| Word count | 6 words from EFF Short Wordlist 1 (1296 entries) |
| Entropy | log₂(1296⁶) ≈ 61.5 bits |
| Bias | Rejection sampling on uint16 — no modulo bias |
| Deterministic | Same key material → same words (verified by test) |

**Findings:**
- The SAS is bound to the TLS session via `ExportKeyingMaterial` with a unique context string (channel ID bytes). An attacker who captures one session's SAS material cannot compute another session's SAS. **Correct.**
- Identicon uses 128 bits (16 bytes) of the same key material, mirrored for visual symmetry. **Correct.**

### 2.6 Integrity Verification (Trailing Hash)

**Implementation:** `pkg/transfer.HashStream`

- SHA-256 computed in parallel during transfer via `io.TeeReader`
- Sender sends hex-encoded hash on QUIC stream after payload
- Receiver verifies before renaming temp file
- Meta.SHA256 field is intentionally empty in the leading metadata (computed during streaming)

**Findings:**
- This prevents the sender from forging a leading hash without knowing the file content first. The trailing hash is computed from the actual bytes sent. **Correct design.**

---

## 3. Network Security

### 3.1 WebSocket Signaling

**Implementation:** `internal/network/signaling.go`, `internal/server/server.go`

| Protection | Implementation |
|---|---|
| Transport | TLS 1.3 only (rejects `ws://`) |
| Server authentication | Certificate fingerprint pinning via `trusted_servers` |
| Client authentication | Channel ID + transfer code (password for CPace) |
| Message size limit | 64 KiB (both client and server) |
| Handshake timeout | 15 seconds |
| Origin check | Rejects connections with `Origin` header (blocks browser CSRF) |
| Idle timeout | 2 minutes (extended on pong) |

**Findings:**
- The `CheckOrigin` function returns `true` only when `Origin` is empty. Non-browser CLI tools don't set `Origin`, so this correctly blocks browser-sourced connections while allowing all legitimate peers. **Effective.**
- Plaintext WebSocket (`ws://`) is rejected early in `dialSignaling`. **Good.**
- Rate limiting applies to WebSocket upgrade (`wsRL`) and to join attempts (`joinRL`). **Defense-in-depth.**

### 3.2 UDP Hole Punching

**Implementation:** `internal/network/network.go`

| Protection | Implementation |
|---|---|
| Probe/ACK nonce | 64 bits derived from session hybrid key via SHA-256 |
| Comparison | `crypto/subtle.ConstantTimeCompare` — prevents timing attacks |
| Probe context | Separate lifetime from main context — NAT mapping kept alive |
| Ticker frequency | 200ms probe intervals — balances responsiveness and bandwidth |

**Findings:**
- The nonce is derived from the hybrid blob key (`SHA-256(hybridKey || "hermod-holepunch-v1")`). Only parties who completed the CPace + hybrid KEM exchange can compute the correct nonce. **Correct.**
- An off-path attacker would need to guess 64 bits per packet to inject a valid probe or ack. Practically unguessable. **Correct.**
- Short packets (< 8 bytes) are silently ignored. **Correct.**

### 3.3 UDP Reflection (CGNAT Address Discovery)

**Implementation:** `internal/network/stun.go`, `internal/server/udp_reflect.go`

| Protection | Implementation |
|---|---|
| Amplification prevention | Two-phase HMAC cookie handshake |
| Cookie binding | HMAC-SHA256(secret, sourceIP)[:8] — bound to source address |
| Key rotation | Daily with 5-minute grace period |
| Rate limiting | Token bucket on cookie-request phase |
| Phase-2 rate limiting | None (only reached after completing cookie challenge) |

**Findings:**
- The two-phase handshake prevents UDP amplification: the external address is NEVER sent to an unverified source. An attacker spoofing a victim's IP would receive the cookie response (9 bytes from 1 byte = 9× amplification), but the cookie is bound to the source IP, so the attacker cannot complete phase 2. **Effective.**
- The rate limiter on phase 1 limits amplification abuse. Phase 2 is not rate-limited because only clients who passed the cookie challenge can reach it. **Correct.**
- However, even 9-byte responses from 1-byte probes is a small amplification factor. At the configured rate limit of 10 req/s with burst 5, the maximum bandwidth amplification is bounded. **Acceptable.**

### 3.4 QUIC Transport

**Implementation:** `internal/network/network.go`

| Protection | Implementation |
|---|---|
| Protocol | QUIC (quic-go v0.59.1) |
| TLS | 1.3 minimum |
| Cipher suites | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| Key exchange | X25519MLKEM768 (PQ hybrid), X25519, CurveP256 |
| Mutual auth | Ephemeral cert fingerprint pinning via `makeCertPinner` |
| Connection binding | Channel ID as ALPN next protocol ("hermod-p2p") |
| Idle timeout | 30 seconds |
| Keepalive | 5 seconds |
| Close errors | Application error codes for cancellation (code 1, "cancelled:sender"/"cancelled:receiver") |

**Findings:**
- `InsecureSkipVerify = true` is intentionally set because standard PKI is replaced by fingerprint pinning. The `VerifyPeerCertificate` callback enforces the fingerprint match using `subtle.ConstantTimeCompare`. **Correct.**
- The sender always dials (QUIC client), the receiver always listens (QUIC server). This asymmetric role assignment prevents simultaneous connection collision. **Correct.**
- The application error codes distinguish sender-cancelled from receiver-cancelled. **Defense-in-depth.**

---

## 4. Server Security

### 4.1 Rate Limiting

**Implementation:** `internal/server/ratelimit.go`

| Property | Implementation |
|---|---|
| Algorithm | Token bucket (per-IP-prefix) |
| IPv4 prefix | /32 |
| IPv6 prefix | /64 |
| Bucket key | HMAC-SHA256(dailySalt, prefix) — raw IPs never stored |
| Salt rotation | Daily UTC — clears all buckets |
| Cleanup | Stale buckets evicted after 30 minutes inactivity |

**Findings:**
- HMAC-hashing the IP prefix before using it as a bucket key prevents raw IP addresses from persisting in memory. The salt rotation limits the window of exposure. **Good privacy design.**
- `rotateSaltIfNeeded` fails open on `crypto/rand` error (logs a warning, reuses the old salt). This is intentional — a failed rotation is preferable to a panic that takes down the server. **Acceptable.**
- Three independent rate limiters: cert endpoint, WebSocket upgrade, join attempts. Each can be separately tuned. **Defense-in-depth.**

### 4.2 Channel Management

**Implementation:** `internal/server/store.go`, `internal/server/server.go`

| Protection | Implementation |
|---|---|
| Channel TTL | Default 600 seconds (configurable) |
| GC interval | 60 seconds (background goroutine) |
| Max blobs per channel | Default 10 (configurable) |
| Max CPace failures | Default 3 (configurable; channel dropped on exceeded) |
| Single receiver | Enforced under lock — prevents duplicate joins |
| Stale waiter cleanup | Purged when channel expires or new allocation occurs |
| Join error messages | Generic "operation failed" — prevents channel enumeration |

**Findings:**
- The single-receiver enforcement uses a lock-and-check pattern that prevents TOCTOU races between two concurrent joins. **Correct.**
- Generic error messages for join failures (non-existent channel, duplicate receiver, transient error) prevent attackers from distinguishing between these cases. **Good.**
- The `MemoryStore` uses a plain `map[uint16]*memChannel`. An attacker could attempt to fill the channel table by allocating many channels. However, with 65535 possible IDs and rate-limited allocation (5 req/s, burst 15), this would require hours of sustained effort. TTL expiry and GC prevent permanent resource exhaustion. **Acceptable.**
- The `dropChannel` function writes error messages to peers while holding the lock, preventing concurrent WebSocket writes (which Gorilla would panic on). **Correct.**

### 4.3 TLS Certificate Management

**Implementation:** `internal/config/config.go`

| Property | Implementation |
|---|---|
| Key type | ECDSA P-256 |
| Validity | 1 year |
| Self-signed | Yes (IsCA = false) |
| Storage | PEM strings in config.yaml |
| File permissions | config.yaml: 0o600, config dir: 0o700 |
| Expiry warnings | 90/30/7-day thresholds (WARN/ERROR/CRITICAL) |

**Findings:**
- Storing the private key in `config.yaml` is an intentional design choice (documented as H-04). The key is ephemeral — regenerated on `hermod serve` if missing. Users requiring stronger isolation can use systemd `LoadCredential` or container volume mounts. **Acceptable with clear documentation.**
- The `IsCA = false` flag prevents the certificate from being used as a CA in any context. **Correct.**
- Cert expiry warnings run at server startup. Periodic checks are not implemented for long-running instances — operators relying on these warnings should restart periodically or monitor via cron. **Low.**
- No CRL/OCSP: self-signed certificates have no revocation mechanism. Compromised server keys require manual `hermod trust` on each client. **By design.**

---

## 5. Configuration and Secrets Management

### 5.1 Config File

| Finding | Impact |
|---|---|
| File permissions: 0o600 | Other users on the same system cannot read private keys |
| Directory permissions: 0o700 | Others cannot list config directory |
| Private key in YAML | Compromise of config file = compromise of server identity |
| Environment variable fallback | `HERMOD_SERVER`, `HERMOD_LISTEN`, etc. can leak via process listing |
| Path fallback (Unix) | `~/.config/hermod/config.yaml` — standard XDG |
| Path fallback (Windows) | `%APPDATA%\Hermod\config.yaml` — standard |
| Emergency fallback | `/tmp/hermod-<uid>` when home dir unavailable |

**Findings:**
- Environment variables (`HERMOD_SERVER`, `HERMOD_LISTEN`, `HERMOD_DB_PATH`, `HERMOD_DEST_DIR`) override config values. While convenient, environment variables can leak via `/proc/self/environ` or child processes. **Low severity — documented trade-off.**
- The emergency fallback to `/tmp/hermod-<uid>` for the config path (when `os.UserHomeDir()` fails) is a reasonable choice over writing to an uncontrolled working directory.

### 5.2 Server Trust Bootstrapping

**Implementation:** `internal/cli/trust.go`

The `hermod trust` command implements Trust On First Use (TOFU):

- Without `--fingerprint`: connects with `InsecureSkipVerify=true`, fetches the cert, and stores its fingerprint. **Vulnerable to MitM on the first connection.** The documentation explicitly warns users to run this over a trusted network.
- With `--fingerprint`: verifies the cert against the provided fingerprint during the TLS handshake. **Secure when the fingerprint is obtained out-of-band.**

**Recommendation:** The TOFU mode is documented and the user is warned. The alternative (`--fingerprint`) provides verification. This is a **medium-severity design consideration** but not a vulnerability per se — it's a conscious trade-off between usability and security.

---

## 6. Input Validation and Hardening

### 6.1 WebSocket Message Handling

- **Message type validation:** `serveClient()` rejects messages that are not `allocate` or `join` as the first message.
- **Blob count limit:** Hard cap of 10 blobs per channel (configurable).
- **Message type enforcement in relay:** Only `MsgBlob` is accepted; unexpected types trigger failure counter increment.
- **Size limits:** 64 KiB max message size on both client and server.
- **JSON parsing:** Gorilla WebSocket's `ReadJSON` is used with `SetReadLimit`.

### 6.2 File I/O Security

- **Path traversal prevention:** `filepath.Base()` strips directory components from the remote filename. `SafeDestinationPath()` applies the same guard as a second layer.
- **Temp file creation:** `os.O_CREATE|os.O_WRONLY|os.O_EXCL` with `0o600` permissions — prevents silently overwriting stale temp files.
- **Temp file cleanup:** On error, cancellation, or hash mismatch, the `.hermod_tmp` file is removed. The final rename only occurs after trailing hash verification.
- **Filename collision handling:** Appends incrementing integer suffix (e.g., `document(1).pdf`) up to 9999.

### 6.3 Transfer Code Validation

- Format: `<uint16>-<word>-<word>-<word>`
- Minimum 3 words enforced
- Channel ID parsed via `fmt.Sscanf` with uint16 validation
- Invalid formats are rejected with descriptive errors

---

## 7. Logging and Information Disclosure

### 7.1 Log Levels

**Implementation:** `internal/cli/verbosity.go`

| Level | Use Case | Security Implication |
|---|---|---|
| `none` | Production default | No structured logging output |
| `error` | Unrecoverable failures | Safe — no secrets |
| `warning` | Rate limiting, missing peer | Safe — generic messages |
| `info` | State changes (channel allocated, etc.) | Channel IDs exposed, but no secrets |
| `debug` | Every internal step | May expose internal state in troubleshooting |

**Findings:**
- Text payloads (`KindText`) are redacted to `<redacted>` in logs. **Good.**
- Keys, passwords, and raw payloads are never logged at any level. **Good.**
- Error messages returned to WebSocket clients are intentionally vague ("operation failed"). **Good.**

### 7.2 Stderr Output

- **printStatus:** User-facing status messages go to stderr. Suppressed by `--quiet`.
- **Progress bars:** Rendered to stderr; suppressed when not a TTY.
- **SAS prompt:** Reads from `/dev/tty` (not stdin) to avoid interference from piped input.

**Findings:** The SAS prompt reads from `/dev/tty` via `openTTY` (Unix) or `CONIN$` (Windows). This prevents piped stdin from corrupting the SAS verification interaction. **Correct.**

---

## 8. Dependency Security

### 8.1 Direct Dependencies

| Package | Version | Purpose | Risk |
|---|---|---|---|
| `github.com/gorilla/websocket` | v1.5.3 | WebSocket | Low — mature, widely used |
| `github.com/quic-go/quic-go` | v0.59.1 | QUIC transport | Moderate — complex protocol implementation |
| `github.com/spf13/cobra` | v1.10.2 | CLI framework | Low — mature |
| `gopkg.in/yaml.v3` | v3.0.1 | YAML config | Low — mature |
| `github.com/schollz/progressbar/v3` | v3.19.0 | Progress UI | Low — no network or crypto |
| `github.com/mattn/go-isatty` | v0.0.22 | TTY detection | Low — trivial |
| `golang.org/x/sys` | v0.45.0 | OS primitives | Low — golang.org |
| `crypto/mlkem` (Go stdlib) | Go 1.25 | ML-KEM-768 | Very low — FIPS 203, stdlib |
| `crypto/tls` (Go stdlib) | Go 1.25 | TLS 1.3 | Very low — stdlib |

### 8.2 Indirect Dependencies

- `filippo.io/nistec` v0.0.4 — constant-time P-256 operations (Filippo Valsorda, respected cryptographer)
- `golang.org/x/crypto` v0.52.0 — crypto utilities
- `golang.org/x/net` v0.54.0 — networking (used by quic-go)

### 8.3 Supply Chain

- All direct dependencies are version-pinned in `go.mod`.
- Go module checksum database (`go.sum`) is maintained.
- No CGO — statically linked binary reduces dependency on system libraries.
- GitHub Actions release workflow pins action versions to major tags (e.g., `@v6`). These are mutable tags and could be overwritten. **Low risk** — actions are from well-known publishers (actions/, official GH).

---

## 9. Medium-Severity Findings

### M-01: TOFU Bootstrap Without Verification Channel

**Location:** `internal/cli/trust.go` — `runTrust()` when `knownFingerprint` is empty.

**Description:** The `hermod trust <server>` command without `--fingerprint` connects with `InsecureSkipVerify=true`. A network-level attacker on the first trust connection can present a different certificate and have its fingerprint pinned.

**Mitigation:** The documentation warns users to run this over a trusted network. The `--fingerprint` flag provides verification when the fingerprint is obtained out-of-band. In practice, the trust command is typically run once during initial setup, often over SSH or LAN where network-level attacks are unlikely.

**Recommendation:** None required — the trade-off is documented and the secure alternative exists.

### M-02: Server Private Key in Config File

**Location:** `internal/config/config.go` — `Save()` writes to `config.yaml` at 0o600.

**Description:** The server's ECDSA P-256 private key is stored as a PEM string within `config.yaml`. Any process running as the same user (or root) can read the private key. A compromised config file exposes the server's long-term identity.

**Mitigation:** File permissions (0o600) restrict access. The key is ephemeral — regenerated if missing. Users needing stronger isolation can use containers, systemd `LoadCredential`, or bind-mount a separate key file.

**Recommendation:** Document recommended isolation methods in the production deployment section. Already addressed in CONTEXT.md (H-04).

### M-03: No Certificate Revocation Mechanism

**Location:** `internal/config/config.go` — self-signed cert with no CRL/OCSP.

**Description:** If a server's private key is compromised, there is no mechanism to revoke the pinned certificate. Each client must manually re-run `hermod trust` to pin a new certificate.

**Mitigation:** The server cert is ephemeral and regenerated on `hermod serve` if missing. Operators can delete the cert from `config.yaml` and restart to generate a new one, then communicate the new fingerprint to clients out-of-band.

**Recommendation:** Consider adding a `--force-regenerate` flag and documenting the recovery procedure in the README. This is a design limitation, not a vulnerability.

---

## 10. Low-Severity Findings

### L-01: Potential UDP Amplification Vector

**Location:** `internal/server/udp_reflect.go` — phase 1 responds with 9 bytes to 1-byte probe.

**Description:** The UDP reflection endpoint responds to cookie requests with a 9-byte response from a 1-byte probe (9× amplification). While rate-limited, an attacker could still use this as a modest amplification vector in a DDoS attack.

**Mitigation:** Rate limiting (10 req/s, burst 5) bounds the abuse potential. The two-phase cookie handshake prevents the more dangerous 7-19 byte address response from being reached by spoofed sources.

**Recommendation:** Consider a lower rate limit or adding a per-client exponential backoff.

### L-02: MemoryStore Channel Table Bounded Only by ID Space

**Location:** `internal/server/store.go` — `map[uint16]*memChannel`.

**Description:** An attacker could attempt to fill the channel table by allocating channels at the maximum rate. With 65535 possible IDs and rate-limited allocation (5 req/s), this would take ~3.6 hours of sustained effort. GC purges expired channels every 60s.

**Mitigation:** Rate limiting and TTL expiry prevent permanent resource exhaustion. The per-IP rate limiter bounds the damage from any single source.

**Recommendation:** Consider adding a cap on total active channels per IP prefix as an additional defense.

### L-03: No Forward Secrecy for WebSocket TLS Session Records

**Location:** `internal/config/config.go` — server uses a persistent certificate.

**Description:** If an attacker records the encrypted WebSocket traffic and later compromises the server's private key, they can decrypt the recorded session. The signaling channel only carries encrypted handshake material (CPace messages, encrypted endpoint bundles), not payload data. Compromise of the server key does NOT reveal payload contents.

**Mitigation:** The signaling payloads are additionally encrypted with the hybrid KEM key (CPace + X25519 + ML-KEM-768). Even with the server TLS key, an attacker would also need to break the per-session hybrid key.

**Recommendation:** Document this in the threat model. The impact is limited by the layered encryption.

### L-04: GitHub Actions Mutable Tag Pins

**Location:** `.github/workflows/release.yml`

**Description:** Action versions are pinned to major version tags (`@v6`, `@v7`, `@v8`). These tags are mutable — a compromised major version could affect the release pipeline.

**Mitigation:** GitHub Actions has supply chain protections (attestations, OIDC). The release pipeline only runs on tag pushes, limiting the blast radius.

**Recommendation:** Pin to full commit SHAs for critical build/publish steps.

---

## 11. Informational Observations

### I-01: Strong Cryptographic Architecture

The three-pillar hybrid KEM (CPace + X25519 + ML-KEM-768) with a split SHA-256 combiner provides robust post-quantum security for the signaling relay phase. This exceeds the security requirements of most P2P file transfer tools and represents a defense-in-depth approach.

### I-02: Clean Separation of Concerns

The codebase separates crypto (PAKE, hybrid KEM, AES-GCM), network (UDP mux, hole punch, QUIC, signaling), server (WebSocket relay, rate limiting, store), and CLI (commands, payload handling) into distinct packages with well-defined interfaces. This aids auditability.

### I-03: Good Test Coverage With Security-Specific Tests

The test suite includes:
- CPace role-separation test (`TestCPaceRoleSeparation`)
- Hybrid KEM wrong-key test (`TestHybridKEMWrongKey`)
- Tampered ciphertext test (`TestOpenTamperedCiphertext`)
- SAS determinism and input-sensitivity tests
- Rate limiter IPv6 prefix sharing test
- Hole punch timing and correctness tests
- QUIC mutual auth round-trip test

### I-04: Constant-Time Comparisons for Secrets

`crypto/subtle.ConstantTimeCompare` is used for:
- Certificate fingerprint verification (`makeCertPinner`)
- Hole punch nonce comparison
- Server certificate pinning in signaling client

This prevents timing side-channel attacks on these critical comparisons.

### I-05: No eval() or Dynamic Code Execution

The Go codebase has no `eval()`, `reflect.Call` on untrusted input, or any form of dynamic code execution. The serialization paths (JSON, YAML) use typed structs with no `interface{}` fields that could enable deserialization attacks.

---

## 12. Recommendations

### Priority 1 (Before Next Release)

1. **Pin CI action versions to commit SHAs** in `.github/workflows/release.yml`. Currently `@v6`/`@v7`/`@v8` mutable tags are used for `actions/checkout`, `actions/setup-go`, etc. While low risk, this is a supply-chain hardening best practice.

2. **Add a per-IP cap on active channels** to the `MemoryStore`. While the current rate limiting bounds allocation speed, an attacker with a botnet could still exhaust the 65535-channel ID space. A limit of ~100 active channels per /32 IPv4 would prevent this without impacting legitimate use. — **[CLOSED 2026-06-12]** Added `MemoryStore.maxChannelsPerIP` (default 100, configurable via `--max-channels-per-ip` flag on `hermod serve`). Per-IP enforcement uses the same `ipPrefix` helper as the rate limiter (IPv4 /32, IPv6 /64). Tracks ownership in `channelOwners` map, decremented on delete and purge. `AllocateChannel` signature extended with `remoteAddr string`. 7 unit tests added.

### Priority 2 (Next Milestone)

3. **Add structured logging of SAS verification outcomes** (success/failure) at `info` level. This helps operators detect potential MitM attacks without needing to enable `debug` logging. — **[CLOSED 2026-06-12]** Added `logInfo`/`logError` calls for all SAS outcomes (confirmed, rejected, cancelled by each side) in `performSASCoordinatedWith` (`internal/cli/tx.go`). Removed redundant caller-side `logInfo("SAS verification passed")` from `runTx`/`runRx`.

4. **Document the server key compromise recovery procedure** in README.md. Include steps for key rotation and client re-trust. — **[CLOSED 2026-06-12]** Added "Server key compromise recovery" section in README.md documenting the procedure (delete cert+key from config, restart server, re-run `hermod trust` on all clients), with a note that auto-renewal does not protect against key compromise since it reuses the same key pair.

### Priority 3 (Nice to Have)

5. **Add support for DNS-based server discovery** as an alternative to hardcoded server URLs, enabling DANE/TLSA for out-of-band trust.

6. **Consider embedding the rate limiter salt's random generation failure handling** — currently falls back silently (logs warning). This is acceptable but could be improved by exposing a metric.

---

## 13. Conclusion

Hermod v0.18.0 demonstrates a mature security posture. The cryptographic design is sound, using modern primitives (CPace PAKE, ML-KEM-768, X25519, AES-256-GCM) with constant-time operations where required. The threat model explicitly assumes an untrusted signaling server, and payloads never pass through it — this zero-knowledge property is correctly implemented.

No critical, high, or medium vulnerabilities were found that require immediate action. The three medium-severity findings (M-01, M-02, M-03) are design trade-offs that are documented and have mitigation paths. The four low-severity findings (L-01 through L-04) are minor hardening opportunities.

The codebase benefits from good test coverage, clear separation of concerns, and consistent use of defensive programming patterns (input validation, size limits, timeouts, constant-time comparisons, proper cleanup).
