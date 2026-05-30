# Security Audit — Hermod Zero-Knowledge File Transfer
**Auditor model:** claude-sonnet-4-6  
**Audit date:** 2026-05-29  
**Codebase version:** 0.7.0  
**Scope:** Full cryptographic and security review of all Go source files

---

## Executive Summary

Hermod is a peer-to-peer file transfer tool with a zero-knowledge signaling layer. The overall security architecture is sound: the signaling server relays only encrypted blobs, QUIC carries the payload over TLS 1.3, and an ephemeral cert fingerprint commitment prevents MitM during the QUIC handshake. Most components are correctly implemented.

However, the audit found **one critical path-traversal vulnerability** that allows a malicious sender to write files to arbitrary receiver filesystem locations. It also found a silent bug where the `role` parameter in the CPace implementation is accepted but never used, and several medium-severity issues in the hash-to-curve, entropy, and rate-limiter subsystems.

---

## Findings by Severity

### CRITICAL

---

#### C-01 — Path Traversal via Received Filename ✅ FIXED

**Files:** `pkg/transfer/transfer.go:82`, `internal/cli/rx.go:372-385`

**Description:**  
The receiver writes the incoming file using `meta.Name` directly from the metadata stream. `filepath.Join` cleans paths but does not strip `..` components that escape the destination directory.

```go
// rx.go
name := meta.Name                                       // trusted from remote peer
destPath = transfer.SafeDestinationPath(destination, name)

// transfer.go
func SafeDestinationPath(dir, name string) string {
    candidate := filepath.Join(dir, name)               // path traversal possible
```

A malicious sender can set `meta.Name = "../../.ssh/authorized_keys"` (or any other path). The sender side uses `filepath.Base` when building metadata from its own filesystem path, but `meta.Name` is transmitted in plaintext over the QUIC stream. Nothing on the receiver side sanitizes the received value. The sender controls the metadata content entirely.

**Attack scenario:**  
1. Sender crafts a metadata struct with `Name: "../../.bash_profile"`.  
2. Receiver with `--destination /tmp/incoming` writes the payload to `/tmp/.bash_profile`.  
3. On Linux, a name like `../../.ssh/authorized_keys` or `../../etc/cron.d/evil` enables remote code execution.

**Fix:**  
Strip directory components from the received name before use.

```go
// In saveToFile, before using meta.Name:
name = filepath.Base(meta.Name)
if name == "" || name == "." || name == ".." {
    name = "received"
}
```

---

### HIGH

---

#### H-01 — CPace `role` Parameter Is Silently Dropped ✅ FIXED

**File:** `internal/crypto/crypto.go:38-61`

**Description:**  
`CPaceInit` accepts a `role` string (`"sender"` or `"receiver"`), but never passes it to `cpaceGenerator`. Both peers compute an identical generator point.

```go
func CPaceInit(password string, channelID uint16, role string) (*CPaceSession, []byte, error) {
    gx, gy, err := cpaceGenerator(password, channelID)  // role dropped silently
```

```go
func cpaceGenerator(password string, channelID uint16) (*big.Int, *big.Int, error) {
    base := fmt.Sprintf("hermod-cpace-v1:%s:%d:", password, channelID)
```

The protocol documentation and test comment acknowledge that role separation is intended as a domain separator to prevent reflection attacks (a sender reflecting its own message to itself). Since both sides use the same generator, a peer could technically call `CPaceFinish` with its own public message and get a key. In the current protocol this produces a different K than the peer's key (the generator is password-bound, not role-bound), so no immediate exploit exists. However, the omission:

- Deviates from RFC 9496 intent.
- Leaves the protocol vulnerable to composition attacks if future changes rely on role separation.
- The test `TestCPaceWrongPassword` acknowledges this silently: "ECDH will succeed but produce a different key."

**Fix:**  
Include `role` in the domain string.

```go
func cpaceGenerator(password string, channelID uint16, role string) (*big.Int, *big.Int, error) {
    base := fmt.Sprintf("hermod-cpace-v1:%s:%d:%s:", password, channelID, role)
```

---

#### H-02 — Hash-to-Curve Is Not Constant-Time (Timing Side Channel) ✅ FIXED

**File:** `internal/crypto/crypto.go:91-123`

**Description:**  
The try-and-increment method reveals, through timing, how many loop iterations were needed to find a valid curve point. The number of iterations is data-dependent on the password hash output. An attacker with microsecond-level timing access can extract partial information about the password.

```go
for ctr := 0; ctr < 256; ctr++ {
    h := sha256.Sum256([]byte(fmt.Sprintf("%s%d", base, ctr)))
    x := new(big.Int).SetBytes(h[:])
    x.Mod(x, p)
    y2 := p256YSquared(x, curve.Params())
    y := modSqrt(y2, p)
    if y == nil {
        continue  // extra iteration leaks timing
    }
```

On average, approximately half of candidate x values have a square root mod p, so the expected number of iterations is 2. Variance reveals information. A remote timing attack over the signaling relay is difficult but not impossible in controlled network conditions.

**Fix:**  
Use the IETF `hash_to_field` method from RFC 9380 with constant-time field arithmetic, or at minimum use Go's `filippo.io/nistec` package which provides constant-time P-256 hash-to-point via SSWU mapping. The current approach is not suitable for a production PAKE implementation.

---

#### H-03 — Transfer Code Wordlist Has Insufficient Entropy and Defects ✅ FIXED

**File:** `internal/crypto/crypto.go:414-465`

**Description:**  
The custom wordlist has three distinct defects that together reduce security below the documented model.

**Defect 1: Wordlist is 255 entries, not 1296 (EFF short wordlist).**  
The array runs from `"acid"` to `"icon"` — 255 unique words. The standard EFF short wordlist has 1,296 words.

**Defect 2: The word `"emit"` appears twice** (line 428). This reduces unique words to 254 and makes `"emit"` appear twice as often.

**Defect 3: Only indices 0–255 are reachable.**  
Word selection uses `int(b) % len(effShortWordlist)` where `b` is a random byte (0–255). With a 255-entry list, `b % 255` gives 0 when `b = 0` and also when `b = 255`. Index 0 (`"acid"`) is selected with 2/256 probability instead of 1/256. Every other word has 1/256. This is a measurable bias.

**Entropy calculation:**  
With 255 effectively unique words and 3-word codes: log₂(255³) ≈ 23.9 bits. The channel ID adds log₂(65536) = 16 bits but the channel ID is public (sent in plaintext in the `allocate` message), so it provides zero password entropy. The usable password entropy is **≈ 24 bits for 3-word codes**, which is marginal against offline attacks if CPace verification is bypassed.

The server limits CPace failures to 3 per channel, making online guessing impractical. The concern is offline attacks if a signaling server log is compromised.

**Fix:**  
Replace the custom list with the full EFF short wordlist (1,296 entries). Use `crypto/rand` to generate indices directly in the range [0, wordlistLen) using rejection sampling rather than byte modulo. This gives log₂(1296³) ≈ 31.9 bits for 3 words and log₂(1296⁵) ≈ 53.1 bits for 5 words.

---

#### H-04 — CPace Shared Secret Does Not Bind Both Public Messages ✅ FIXED

**File:** `internal/crypto/crypto.go:76-80`

**Description:**  
After ECDH, the shared key K is derived by hashing only the x-coordinate:

```go
iskX, _ := curve.ScalarMult(peerX, peerY, s.scalar)
h := sha256.Sum256(padTo32(iskX))
k := h[:]
```

RFC 9496 CPace derives the Intermediate Session Key as:  
`ISK = HASH(ISK_x || Ya || Yb)` — binding both parties' public messages into the key.

Without this binding, the key does not prove that both parties exchanged the same messages. In the current protocol, this is partially mitigated by the AES-GCM authentication step (if either message was tampered with, decryption fails). However, the omission weakens the formal security proof and leaves the door open to subtle attacks in future protocol extensions.

**Fix:**  
Derive K as `SHA256(x_coordinate || sender_pub || receiver_pub)`. This requires passing both public messages into `CPaceFinish`.

---

### MEDIUM

---

#### M-01 — Server Certificate Is Marked CA with 10-Year Validity ✅ FIXED

**File:** `internal/config/config.go:151-158`

```go
tmpl := &x509.Certificate{
    NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),  // 10 years
    IsCA:     true,
}
```

The signaling server's self-signed certificate is marked as a CA and is valid for 10 years. A private-key compromise allows an attacker to issue arbitrary certificates trusted by clients that pinned this cert, for 10 years without revocation.

**Fix:**  
Set `IsCA: false`. Set validity to 1–2 years. Add a flag to regenerate the cert manually.

---

#### M-02 — AES-GCM Endpoint Bundle Has No Additional Authenticated Data ✅ FIXED

**File:** `internal/crypto/crypto.go:207-224`, `internal/cli/tx.go:214`, `internal/cli/rx.go:211`

```go
ct := gcm.Seal(nonce, nonce, plaintext, nil)  // nil AAD
```

The AES-GCM seal for the endpoint bundle uses no Additional Authenticated Data. Including the channel ID as AAD would prevent a replay of a ciphertext captured from one session being replayed in another session with the same CPace key (which is astronomically unlikely given the key space, but is a defense-in-depth measure). Without AAD, the ciphertext is transferable across any context that holds the same K.

**Fix:**  
Pass the channel ID (as a 2-byte big-endian value) as the AAD to `gcm.Seal` and `gcm.Open`.

---

#### M-03 — Rate Limiter Bucket Map Is Unbounded ✅ FIXED

**File:** `internal/server/ratelimit.go:18-98`

```go
type RateLimiter struct {
    buckets map[string]*bucket  // grows without bound within a UTC day
```

The `buckets` map grows for every distinct IP prefix seen during a UTC day. The `Cleanup` method exists but is never called from `runServe`. An attacker with many source IPs (e.g., a botnet or spoofed UDP sources) can fill the map before daily rotation. Each entry is approximately 100 bytes; 2³² IPv4 prefixes would exhaust memory.

**Fix:**  
Call `rl.Cleanup(maxAge)` on a background ticker in `runServe`, or enforce a maximum map size (e.g., 1,000,000 entries) with LRU eviction.

---

#### M-04 — Channel ID Exhaustion (DoS)

**File:** `internal/server/store.go:48-56`

The channel ID is a `uint16`, giving 65,536 possible channels. A distributed attacker can allocate all channels by sending `allocate` messages. The rate limiter (5 req/s per IP) requires only ~13,100 source IPs to exhaust the space in one second. With a 10-minute TTL, this sustains a full denial-of-service indefinitely.

**Fix:**  
Increase channel ID to `uint32` (4 billion channels). Add a per-IP channel allocation limit (e.g., 10 active allocations per /32 per day).

---

#### M-05 — `handleJoin` Does Not Validate Channel Existence ✅ FIXED

**File:** `internal/server/server.go:225-246`

The `handleJoin` handler adds the receiver to `s.waiters[channelID]` and sends `MsgOK` without verifying that the channel was previously allocated via `AllocateChannel`. A receiver joining a nonexistent channel receives `MsgOK`, enters the relay loop, and waits indefinitely for a sender that may never arrive.

```go
func (s *Server) handleJoin(conn *websocket.Conn, remoteAddr string, channelID uint16, _ []byte) {
    // No check against s.store for channel existence
    conn.WriteJSON(Message{Type: MsgOK, ChannelID: channelID, Payload: payload})
```

**Fix:**  
Call `s.store.FetchBlob` or a dedicated `ChannelExists` method before returning `MsgOK`.

---

#### M-06 — `/cert` Endpoint Is Dead Code and Always Returns an Error ✅ FIXED

**File:** `internal/server/server.go:145-155`

```go
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
    if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
        if r.TLS != nil && len(r.TLS.TLSUnique) > 0 {
            http.Error(w, "no cert", http.StatusNotFound)
            return
        }
    }
    http.Error(w, "use /cert endpoint over TLS", http.StatusOK)
}
```

This handler always falls through to the final `http.Error`. The first branch's inner condition (`r.TLS.TLSUnique`) is always nil in TLS 1.3 (TLSUnique was removed). No code path returns the server certificate. The `FetchServerFingerprint` function in `network/signaling.go` works around this by opening a second raw TLS connection, which is an inefficient double-connection hack.

**Fix:**  
Implement the endpoint correctly by reading `r.TLS.PeerCertificates[0]` (after requiring mutual TLS) or by storing the server cert DER in the `Server` struct and serving it directly. Alternatively, remove the endpoint and document the fingerprint trust bootstrapping path clearly.

---

#### M-07 — stdin Payload Buffers Entire Input in Memory ✅ FIXED

**File:** `internal/cli/tx.go:409-419`

```go
case transfer.KindStream:
    scanner := bufio.NewReader(os.Stdin)
    buf, err := io.ReadAll(scanner)  // entire stdin loaded into RAM
```

When sending piped stdin, the sender reads all data into memory before computing the SHA-256 hash for the metadata. A 10 GB piped input will allocate 10 GB of RAM. This is a self-inflicted DoS for large streams.

**Fix:**  
Hash stdin with a streaming SHA-256 and write bytes directly to the QUIC stream simultaneously. Send a sentinel hash of `0000...` in metadata if hashing must complete before sending, then send an integrity stream after. Alternatively, send size and hash in a trailing metadata message after the payload.

---

### LOW

---

#### L-01 — SAS Keying Material Has No Session Context Binding ✅ FIXED

**File:** `internal/cli/tx.go:567`

```go
material, err := tlsState.ExportKeyingMaterial("hermod-sas-v1", nil, 32)
```

The `context` parameter (second argument) is `nil`. Binding the channel ID or endpoint bundle hash as context would further couple the SAS to the specific session, preventing a theoretically replayed TLS session from showing the same SAS.

**Fix:**  
Pass the channel ID bytes as context: `tlsState.ExportKeyingMaterial("hermod-sas-v1", channelIDBytes, 32)`.

---

#### L-02 — RSA-2048 for Ephemeral Certs (Prefer ECDSA P-256) ✅ FIXED

**Files:** `internal/cli/tx.go:438`, `internal/config/config.go:143`

Both ephemeral QUIC certificates and the signaling server certificate use RSA-2048 (`rsa.GenerateKey(rand.Reader, 2048)`). RSA-2048 key generation is significantly slower than ECDSA P-256, and the signatures are larger. For ephemeral keys discarded after 24 hours, P-256 provides equivalent security with faster generation and smaller wire footprint.

**Fix:**  
Replace with `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`.

---

#### L-03 — `randScalar` Uses Biased Modular Reduction (Loop Never Iterates) ✅ FIXED

**File:** `internal/crypto/crypto.go:187-200`

```go
k.Mod(k, new(big.Int).Sub(n, big.NewInt(1)))
k.Add(k, big.NewInt(1))
if k.Sign() > 0 && k.Cmp(n) < 0 {  // always true — loop exits every time
    return k, nil
}
```

After `Mod(k, n-1)`, k ∈ [0, n-2]. After `Add(1)`, k ∈ [1, n-1]. The guard `k.Sign() > 0 && k.Cmp(n) < 0` is always true, so the retry loop never runs. The `Mod` introduces a small bias: values in [0, (2²⁵⁶ mod n) - 1] are slightly overrepresented. For P-256, the bias is ≈ 1/2¹²⁸, which is cryptographically negligible. However, the code structure (an infinite loop that never retries) is misleading and masks the bias.

**Fix:**  
Use proper rejection sampling: generate a random 32-byte value; if it is less than n, accept it; otherwise retry. This is unbiased and correctly communicates the algorithm's intent.

---

#### L-04 — Multiple Receivers Can Join the Same Channel ✅ FIXED

**File:** `internal/server/server.go:225-246`

No limit prevents multiple connections from joining the same channel as receivers. Multiple actors can monitor the blob relay for a given channel. Because all blobs are AES-GCM encrypted under the CPace key, a passive eavesdropper gains nothing beyond traffic metadata. However, a legitimate receiver could be displaced if a later joiner receives the blob first and the sender moves on.

**Fix:**  
Reject a `join` if a receiver is already registered for `channelID`.

---

#### L-05 — Trust-On-First-Use for Signaling Server ✅ FIXED

**File:** `internal/cli/trust.go:34-37`, `internal/network/signaling.go:203-239`

```go
func runTrust(serverArg string) error {
    fp, err := network.FetchServerFingerprint(serverURL)  // InsecureSkipVerify: true
```

The `trust` command connects with TLS verification disabled to fetch the server certificate fingerprint. An attacker positioned on the network at the time of the first `trust` command can present their own certificate and have it pinned. This is the classic TOFU bootstrap problem.

This is documented in `docs/protocol.md`: *"Connections to an unknown server are accepted on first use and the fingerprint is saved."* The limitation is known. It means the security model requires a trusted initial network path for the `trust` operation.

**Recommendation:**  
Document explicitly in the README that `hermod trust` should be run over a trusted network (e.g., VPN, physical LAN, or verified out-of-band). Consider supporting a `--fingerprint` flag to `trust` that accepts a pre-known fingerprint and verifies it instead of accepting blindly.

---

#### L-06 — WebSocket Upgrader Accepts All Origins ✅ FIXED

**File:** `internal/server/server.go:85-88`

```go
upgrader: websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
},
```

The `CheckOrigin` hook allows any web page to open a WebSocket to the signaling server from a browser. This is not exploitable beyond what the WebSocket protocol allows (authenticated requests still require a CPace key), but it exposes the server to cross-site WebSocket hijacking from arbitrary web origins. For a non-browser service this is a low risk, but it is unnecessary permissiveness.

**Fix:**  
Return `r.Header.Get("Origin") == ""` to reject browser-sourced cross-origin connections, or drop `CheckOrigin` from the Upgrader configuration entirely (the Gorilla default rejects cross-origin requests).

---

#### L-07 — Hole Punch Probe Values Are Fixed and Predictable ✅ FIXED

**File:** `internal/network/network.go:147-148`

```go
probe := []byte{probeMarker, 0xAB}
ack   := []byte{probeMarker, 0xCD}
```

Fixed probe and ack bytes allow an attacker who can send UDP packets to a client's bound port to trigger a fake hole-punch success. The attacker would need to present the legitimate peer's ephemeral TLS certificate during the subsequent QUIC handshake, which they cannot do. So the cert pinning step catches this. The risk is limited to causing the client to attempt a QUIC connection to a wrong address (connection will fail at TLS).

**Fix:**  
Use a session-unique nonce (e.g., the first 4 bytes of the CPace public message) as the probe payload. This makes probe packets unguessable and prevents spoofed ack injection.

---

#### L-08 — `WithContext` Goroutine Can Leak with Non-Cancellable Context ✅ FIXED

**File:** `internal/network/signaling.go:85-93`

```go
go func() {
    <-ctx.Done()
    _ = c.conn.SetReadDeadline(time.Unix(0, 0))
}()
```

If `WithContext` is called with `context.Background()` or a context that is never cancelled, the goroutine blocks forever on `<-ctx.Done()`. In the current codebase, callers always pass cancellable contexts (`signal.NotifyContext`), so this does not manifest. However, any future caller using a non-cancellable context will leak a goroutine and prevent garbage collection of the WebSocket connection.

**Fix:**  
Add a `done` channel to the `SignalingClient` and close it in `Close()`. The goroutine should select on both `ctx.Done()` and the `done` channel.

---

## Cross-Cutting Observations

### What the design gets right

- **Zero-knowledge relay.** The signaling server never holds plaintext endpoint or payload data. CPace ensures the password never crosses the network. All sensitive data is encrypted before relay.
- **Cert fingerprint pinning.** Exchanging ephemeral QUIC cert fingerprints inside the AES-GCM-protected endpoint bundle is the correct binding mechanism. A MitM cannot substitute its own certificate without breaking the CPace-derived key.
- **TLS 1.3 enforcement.** `MinVersion: tls.VersionTLS13` is set everywhere. The cipher and curve preferences correctly prefer `X25519MLKEM768` (post-quantum hybrid) then `X25519`.
- **Integrity verification.** SHA-256 is computed before transmission and verified via `VerifyStream` with a temp-file-then-rename approach. Partial files are cleaned up on any error.
- **Rate limiting with IP anonymization.** HMAC-SHA256(daily-rotating-salt, IP-prefix) as the bucket key is a strong approach to rate limiting without storing raw IPs.
- **CPace failure circuit-breaker.** Three CPace failures drop the channel. This effectively blocks online brute-force attempts per channel.
- **SAS out-of-band verification.** The SAS is derived from `ExportKeyingMaterial`, which is bound to the full TLS session. The identicon adds a visual confirmation channel. The symmetric enforcement (either side can require it) is correctly implemented.
- **Graceful cancellation.** QUIC `ApplicationError` with typed cancellation codes allows either peer to abort cleanly and notify the other.

### Architecture-level gap: no post-quantum PAKE

The TLS 1.3 layer correctly uses X25519MLKEM768 (hybrid post-quantum KEM). However, the CPace handshake over P-256 is purely classical. A quantum adversary who records the signaling relay traffic could retroactively break CPace and recover the CPace key K, which then decrypts the endpoint bundle. Since the endpoint bundle contains only network addresses (not payload), the impact is limited — but the asymmetry is worth noting for long-term security posture.

---

## Finding Summary Table

| ID   | Severity | File(s)                              | Title                                                 |
|------|----------|--------------------------------------|-------------------------------------------------------|
| C-01 | Critical | `pkg/transfer/transfer.go`, `cli/rx.go` | Path traversal via received filename ✅ |
| H-01 | High     | `internal/crypto/crypto.go`          | CPace `role` parameter silently dropped ✅ |
| H-02 | High     | `internal/crypto/crypto.go`          | Hash-to-curve not constant-time (timing side channel) ✅ |
| H-03 | High     | `internal/crypto/crypto.go`          | Transfer code wordlist has low entropy and defects ✅ |
| H-04 | High     | `internal/crypto/crypto.go`          | CPace shared secret does not bind both public messages ✅ |
| M-01 | Medium   | `internal/config/config.go`          | Server cert: IsCA=true, 10-year validity ✅ |
| M-02 | Medium   | `internal/crypto/crypto.go`, `cli/*` | AES-GCM endpoint bundle has no AAD ✅ |
| M-03 | Medium   | `internal/server/ratelimit.go`       | Rate limiter bucket map unbounded ✅ |
| M-04 | Medium   | `internal/server/store.go`           | Channel ID space exhaustion (uint16 = 65536 max) |
| M-05 | Medium   | `internal/server/server.go`          | `handleJoin` does not validate channel existence ✅ |
| M-06 | Medium   | `internal/server/server.go`          | `/cert` endpoint is dead code ✅ |
| M-07 | Medium   | `internal/cli/tx.go`                 | stdin stream buffers entire input in RAM ✅ |
| L-01 | Low      | `internal/cli/tx.go`                 | SAS keying material lacks session context binding ✅ |
| L-02 | Low      | `internal/cli/tx.go`, `config/config.go` | RSA-2048 for ephemeral certs (prefer ECDSA P-256) ✅ |
| L-03 | Low      | `internal/crypto/crypto.go`          | `randScalar` uses biased reduction, loop never retries ✅ |
| L-04 | Low      | `internal/server/server.go`          | Multiple receivers can join the same channel ✅ |
| L-05 | Low      | `internal/cli/trust.go`              | Trust-On-First-Use bootstrap ✅ |
| L-06 | Low      | `internal/server/server.go`          | WebSocket upgrader accepts all origins ✅ |
| L-07 | Low      | `internal/network/network.go`        | Hole punch probe/ack bytes are fixed and guessable ✅ |
| L-08 | Low      | `internal/network/signaling.go`      | `WithContext` goroutine can leak on non-cancellable ctx ✅ |

---

## Recommended Priority Order for Fixes

1. **C-01** ✅ — Fix path traversal immediately. One line: `name = filepath.Base(meta.Name)` in `saveToFile`.
2. **H-03** ✅ — Replace the custom wordlist with the full 1,296-word EFF short list and use rejection sampling for index selection.
3. **H-01** ✅ — Pass `role` into `cpaceGenerator` to restore intended domain separation.
4. **H-04** ✅ — Bind both public messages into the ISK derivation.
5. **H-02** ✅ — Replace try-and-increment with a constant-time hash-to-curve (RFC 9380 SSWU).
6. **M-01** ✅ — Remove `IsCA: true`; reduce cert validity to 1 year.
7. **M-02** ✅ — Add channel ID as AAD to `crypto.Seal` / `crypto.Open` for endpoint bundles.
8. **M-03** ✅ — Add `Cleanup` ticker in `runServe`.
9. **M-04** — Increase channel ID to `uint32`. *(deferred)*
10. **M-05** ✅ — Validate channel existence in `handleJoin`.
11. **M-06** ✅ — Fix `/cert` endpoint to serve actual DER certificate.
12. **M-07** ✅ — Compute hash in parallel during streaming; send as trailing metadata stream.
