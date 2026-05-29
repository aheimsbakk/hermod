# Hermod security audit

Date: 2026-05-29
Auditor: GPT-5.4
Scope: code review of the current repository, with focus on the zero-knowledge / zero-trust file-transfer design, cryptography, signaling, transport, file handling, and operational security.

## Executive summary

Hermod has a solid high-level design: the payload stays off the signaling server, endpoint data is encrypted before relay, peer-to-peer transport uses QUIC with TLS 1.3, peer certificates are pinned, temp files are cleaned up on failure, and the codebase has broad test coverage.

That said, the current build is **not ready to claim strict "zero-knowledge, zero-trust" security**.

Three issues stand out:

1. **High** — the receiver trusts a sender-controlled filename and can write outside the chosen destination directory.
2. **High** — channel state on the signaling server is weak: a client can join a channel before it exists, and the server does not enforce exactly one sender and one receiver.
3. **High** — the PAKE is described as CPace/RFC 9496, but the implementation is a custom variant. The `role` input is ignored, and key derivation lacks the transcript binding expected from a standard PAKE.

Because of those issues, my verdict is:

- **Confidentiality:** good after a correct handshake.
- **Integrity:** mostly good, but inconsistent in stdout paths.
- **Peer authentication:** partially good, but the PAKE claim is overstated.
- **Relay trust model:** untrusted for payload confidentiality, but still able to cause targeted denial of service and first-use trust attacks.
- **Overall readiness for a security-sensitive release:** **not yet**.

## What I reviewed

- Protocol and architecture docs: `README.md`, `docs/protocol.md`, `BLUEPRINT.md`, `CONTEXT.md`
- Crypto: `internal/crypto/crypto.go`
- Signaling and transport: `internal/network/*.go`, `internal/server/*.go`
- CLI transfer flow: `internal/cli/tx.go`, `internal/cli/rx.go`, `internal/cli/trust.go`
- File handling and metadata: `pkg/transfer/transfer.go`
- Tests across crypto, network, server, CLI, and end-to-end packages

## Validation performed

- `go test ./...` ✅ passed
- `go test -race ./...` ⚠️ could not run in this environment because CGO is disabled
- `govulncheck` ⚠️ not available in this environment

## Security strengths

- Payload bytes do not traverse the signaling server.
- Endpoint bundles are encrypted with AES-256-GCM before relay.
- QUIC uses TLS 1.3 and pins the peer certificate fingerprint.
- Server cert pinning is enforced for `tx` and `rx` after `trust`.
- Temp files are removed on integrity failure and on cancellation.
- Config files are written with restrictive permissions (`0700` dir, `0600` file).
- Rate-limiter bucket keys do not store raw IPs directly.
- The project has useful unit, integration, and e2e coverage.

## Findings

| ID | Severity | Title |
|---|---|---|
| F-01 | High | Sender-controlled filename can escape the destination directory |
| F-02 | High | Signaling server allows channel squatting and multi-peer channel confusion |
| F-03 | High | The PAKE is not standard CPace despite being documented as RFC 9496 |
| F-04 | Medium | First-use `trust` is TOFU and can pin an attacker's certificate |
| F-05 | Medium | Payload hash verification is skipped for stdout paths |
| F-06 | Medium | stdin transfers are buffered fully in memory |
| F-07 | Low | TLS 1.3 cipher suite settings are likely ineffective in Go |
| F-08 | Low | Server logs expose raw client IPs despite the privacy-focused design |

---

## F-01 — Sender-controlled filename can escape the destination directory

**Severity:** High

### Evidence

- `internal/cli/rx.go:373-387`
- `pkg/transfer/transfer.go:80-95`

The receiver uses `meta.Name` from the network as a file path component:

- `saveToFile()` sets `name := meta.Name`
- `SafeDestinationPath()` does `filepath.Join(dir, name)`
- there is **no sanitization** that strips `..`, absolute paths, or separators

### Impact

A malicious sender can make the receiver write outside the chosen directory.

Examples:

- destination `.` + filename `../../.ssh/authorized_keys`
- destination `/downloads` + filename `../.bashrc`

This can overwrite arbitrary files that the receiving user can write.

### Why this matters

The receiver must treat metadata as untrusted input. In a zero-trust design, a remote peer must never control local filesystem paths.

### Fix

- Sanitize incoming names to a basename only.
- Reject absolute paths.
- Reject any path that escapes the destination after `filepath.Clean`.
- Consider replacing unsafe names with a generated safe fallback.

---

## F-02 — Signaling server allows channel squatting and multi-peer channel confusion

**Severity:** High

### Evidence

- `internal/server/server.go:225-245`
- `internal/server/server.go:233-245`
- `internal/server/server.go:303-314`
- `internal/crypto/crypto.go:453`

Problems:

1. `handleJoin()` does not verify that the channel was allocated in the store before it returns `MsgOK`.
2. The server does not enforce exactly one sender and one receiver per channel.
3. Blob forwarding picks the **first** opposite-side waiter, which makes channel behavior order-dependent.
4. Channel IDs are only `uint16`.

### Impact

An attacker can:

- pre-join channels that do not exist yet
- keep those WebSockets open
- break future transfers when a real sender later allocates the same ID
- race the intended receiver and become the active peer for relay traffic
- deny service at scale because the channel ID space is only 65,536 values

Confidentiality still benefits from the PAKE and peer cert pinning, but availability and session correctness are weak.

### Why this matters

For an "untrusted relay" design, the relay should not be able to trivially break channel state or allow ambiguous peer membership.

### Fix

- Reject `join` unless the channel exists in the store.
- Enforce one sender and one receiver per channel.
- Bind channel state to explicit roles.
- Expire or reject orphan waiters.
- Consider increasing channel ID size substantially.

---

## F-03 — The PAKE is not standard CPace despite being documented as RFC 9496

**Severity:** High

### Evidence

- `internal/crypto/crypto.go:3-6`
- `internal/crypto/crypto.go:38-43`
- `internal/crypto/crypto.go:89-97`
- `docs/protocol.md:76-88`

The code and docs say this is CPace / RFC 9496. The implementation does not match that claim.

Key gaps:

1. `CPaceInit(password, channelID, role)` accepts `role`, but `role` is ignored.
2. The generator only mixes `password` and `channelID`.
3. Shared key derivation is `SHA-256(x-coordinate)` of a scalar multiplication result, without a transcript-bound KDF.
4. There is no explicit key confirmation step at the PAKE layer.

This is closer to a **custom password-derived-generator ECDH** than to standard CPace.

### Impact

- The documented security claim is stronger than the code supports.
- Security review and interoperability assumptions are unsafe.
- Reflection and transcript-confusion risks are higher than they should be in a standard PAKE.

I did **not** find a direct passive key-recovery attack from this code review alone, but this is still a high-risk cryptographic design issue because the protocol is custom while being labeled as standard.

### Why this matters

Custom PAKEs are easy to get subtly wrong. When a system says "CPace", reviewers assume RFC 9496 properties. That assumption is not justified here.

### Fix

- Replace this with a real, reviewed CPace implementation or another standard PAKE.
- If you keep a custom design temporarily, stop calling it CPace/RFC 9496 in code and docs.
- Bind role, channel, both public messages, and context into the final KDF.
- Add an explicit authenticated key confirmation step.

---

## F-04 — First-use `trust` is TOFU and can pin an attacker's certificate

**Severity:** Medium

### Evidence

- `internal/cli/trust.go:25-51`
- `internal/network/signaling.go:41-55`
- `internal/network/signaling.go:213-239`

`trust` fetches the server fingerprint over a connection with `InsecureSkipVerify: true`, then stores that fingerprint as trusted with no out-of-band check.

### Impact

An active attacker present during the first `hermod trust` can cause the client to pin the attacker's certificate.

After that, `tx` and `rx` will trust the wrong relay.

### Why this matters

This is classic TOFU. It is workable for some tools, but it is not strict zero-trust bootstrapping.

### Fix

At minimum:

- describe this as TOFU, not full zero-trust bootstrapping
- show the fingerprint and require manual confirmation
- prefer an out-of-band fingerprint or a pre-shared trust root for production use

---

## F-05 — Payload hash verification is skipped for stdout paths

**Severity:** Medium

### Evidence

- `internal/cli/rx.go:339-365`
- `internal/cli/rx.go:409-417`

Integrity verification with `transfer.VerifyStream()` only happens in `saveToFile()`.

When:

- destination is empty and stdout is piped, or
- destination is empty and interactive mode prints text/stream payloads,

the code uses `io.Copy()` directly and does not verify `meta.SHA256`.

### Impact

- Behavior does not match the protocol docs, which say the receiver verifies SHA-256 on arrival.
- Integrity handling is inconsistent by output mode.

This is not as severe as a transport-authentication failure because QUIC/TLS already protects the session, but it does break a documented security property.

### Fix

- Verify the stream hash in all receive modes.
- If output must stream directly to stdout, compute the hash while copying and fail clearly at the end.
- Update docs if stdout mode is intentionally best-effort.

---

## F-06 — stdin transfers are buffered fully in memory

**Severity:** Medium

### Evidence

- `internal/cli/tx.go:409-419`

For `KindStream`, the sender reads all stdin into memory with `io.ReadAll()` before sending.

### Impact

- Large piped input can exhaust memory.
- A claimed "stream" transfer is not actually streaming on the sender side.
- This weakens reliability under untrusted or accidental large input.

### Fix

- Use a bounded temp-file strategy for stdin.
- Or redesign metadata flow so the sender does not need the full payload in memory before transfer.

---

## F-07 — TLS 1.3 cipher suite settings are likely ineffective in Go

**Severity:** Low

### Evidence

- `internal/config/config.go:131-137`

The config exposes `CipherSuites`, but the process enforces `MinVersion: tls.VersionTLS13`.

In Go, `tls.Config.CipherSuites` traditionally controls TLS 1.0-1.2 suites, not TLS 1.3 suites. If that behavior still applies here, the configured TLS 1.3 cipher list is not actually enforced.

### Impact

This is mainly a **false-control** issue: operators may think they are enforcing a suite policy when they are not.

### Fix

- Confirm the behavior against the Go version in use.
- If TLS 1.3 suites are not configurable, remove or clearly document that field.

---

## F-08 — Server logs expose raw client IPs despite the privacy-focused design

**Severity:** Low

### Evidence

- `internal/server/server.go:213`
- `internal/server/server.go:230`

The server logs `sender_ip` and `receiver_ip` directly.

### Impact

This does not break payload confidentiality, but it weakens the privacy story. The docs emphasize that IP addresses are not stored directly in rate-limit buckets, while server logs still contain the raw addresses.

### Fix

- Avoid logging raw IPs by default.
- If logs are needed for operations, gate them behind debug mode or hash them.

---

## Crypto-specific assessment

### What is good

- AES-256-GCM use is straightforward and nonce generation uses `crypto/rand`.
- Peer cert pinning over QUIC is a strong design choice.
- SAS uses exported keying material from the live TLS session, which is the right place to derive a session-bound display value.

### What needs work

- The project should stop calling the PAKE "CPace" until it actually matches a standard construction.
- The design depends heavily on the security of a custom PAKE implementation.
- The optional SAS step is useful for active MITM detection, but the baseline authenticated key exchange should not rely on a custom construction.

## Zero-knowledge / zero-trust claim assessment

### Zero-knowledge

**Partially true, but too strong as written.**

The relay does not see payload bytes, which is good. But the relay still sees:

- channel allocation and timing
- public IPs
- message counts and sizes
- handshake traffic it can interfere with

So this is better described as:

> end-to-end encrypted peer-to-peer transfer with an untrusted signaling relay

not as strict zero-knowledge in the formal sense.

### Zero-trust

**Not yet.**

Why:

- first-use server trust is TOFU
- receiver trusts sender-controlled file metadata too much
- signaling channel membership rules are weak
- the PAKE is custom while documented as standard

## Recommended priority order

1. **Fix F-01**: sanitize filenames and prevent directory escape.
2. **Fix F-02**: require existing channels for join and enforce exactly two peers with fixed roles.
3. **Fix F-03**: replace or redesign the PAKE, and stop claiming RFC 9496 until that is true.
4. **Fix F-05**: verify payload hashes in all receive modes.
5. **Fix F-04**: harden `trust` bootstrapping and document TOFU clearly.
6. **Fix F-06**: remove unbounded stdin buffering.

## Final verdict

Hermod has a promising architecture and several good security choices, but it is **not yet ready for a strong security claim** such as "zero-knowledge, zero-trust file transfer".

The main blockers are:

- arbitrary file-write risk on the receiver
- weak signaling channel state enforcement
- a custom PAKE presented as standard CPace

Fix those first. After that, reassess the protocol claims and rerun the audit.
