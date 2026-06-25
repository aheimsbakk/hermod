# Hermod Security Audit

**Model:** opencode/glm-5.2
**Date:** 2026-06-25
**Scope:** Full source tree — `cmd/`, `internal/` (cli, config, crypto, network, server), `pkg/transfer/`, `e2e/`, `scripts/`, `docs/`.
**Version audited:** 1.0.5 (Go 1.25.0)
**Method:** Manual source review of all security-relevant modules, cross-referenced with prior audits in `docs/audits/`. Static checks: `go vet ./...` (clean), `go build ./...` (clean), `go test ./internal/... ./pkg/...` (passing).

---

## Executive Summary

Hermod is a peer-to-peer file/text transfer tool built on QUIC + TLS 1.3 with a hybrid post-quantum key exchange (CPace + X25519 + ML-KEM-768) and a self-hosted signaling relay. The cryptographic architecture is sound and well-aligned with its threat model: the signaling server is zero-knowledge with respect to payload and endpoint data, peer identity is pinned via SPKI fingerprints, and an optional SAS channel detects active MITM.

No Critical or High severity issues were found. The report identifies **3 Medium** and **14 Low** findings, plus re-confirms 8 previously tracked items. Of the new findings, the most actionable is **M-01** (a latent panic in the stale-waiter cleanup loop that could crash the server). The remainder are hardening recommendations and re-validations of previously accepted/open items.

### Positive observations

- **Zero-knowledge relay.** Endpoint bundles are encrypted with `DeriveHybridBlobKey` (SHA-256 split combiner over CPace ‖ X25519 ‖ ML-KEM); the server only relays opaque blobs. `internal/crypto/crypto.go:286`, `internal/cli/tx.go:331`.
- **Post-quantum by default, no classical fallback.** TLS curve preferences force `X25519MLKEM768`; `MinVersion: tls.VersionTLS13`. `internal/config/config.go:138`.
- **SPKI pinning survives cert renewal** and uses `crypto/subtle.ConstantTimeCompare`. `internal/network/network.go:403`.
- **UDP reflector blocks amplification** via a two-phase HMAC cookie handshake bound to source IP, with daily key rotation and 5-minute grace. `internal/server/udp_reflect.go`.
- **TOCTOU-safe duplicate-receiver join** (check-and-insert under one lock). `internal/server/server.go:370`.
- **Path-traversal defense in depth** — `filepath.Base` applied at both `rx.go:569` and `transfer.go:85`.
- **Atomic file writes** — temp file created with `O_CREATE|O_WRONLY|O_EXCL` at `0o600`, renamed only after SHA-256 verification. `internal/cli/rx.go:586`. The `O_EXCL` + remove + retry pattern defeats symlink-planting at the temp path; `os.Rename` does not follow the destination symlink.
- **SAS bound to the TLS session** via `ExportKeyingMaterial("hermod-sas-v1", channelID, 32)`; symmetric enforcement; reads from `/dev/tty`. `internal/cli/tx.go:808`, `internal/cli/tty_unix.go:12`.
- **Privacy-preserving rate limiting** — bucket keys are `HMAC-SHA256(dailySalt, ipPrefix)`; raw IPs are never stored. `internal/server/ratelimit.go:106`.
- **Bounded everywhere** — 64 KiB signaling messages, 1 MiB metadata, 8 KiB cert response, 256-byte trailing hash, 10 blobs/channel, 3 CPace failures, 100 channels/IP, 30 s QUIC idle, 10 s/30 s HTTP timeouts.
- **No secrets in source.** Text input is redacted in logs (`tx.go:118`); transfer-code password is never logged; env vars drive all config.

---

## Findings

### MEDIUM

---

#### ~~M-01: Stale-waiter cleanup loop can panic and crash the server (DoS)~~ **FIXED**

**Location:** `internal/server/server.go:295-306`

**Description:** `handleAllocate` removes stale waiters for a channel while iterating with `for i, w := range s.waiters[channelID]`. The `range` clause captures the slice length at loop entry, but the body mutates the slice in place using swap-with-last plus `s.waiters[channelID] = s.waiters[channelID][:len-1]`:

```go
for i, w := range s.waiters[channelID] {
    if w.conn == conn { continue }
    ...
    s.waiters[channelID][i] = s.waiters[channelID][len(s.waiters[channelID])-1]
    s.waiters[channelID] = s.waiters[channelID][:len(s.waiters[channelID])-1]
}
```

When two or more stale waiters are removed, `i` advances past the shrinking slice length and the assignment `s.waiters[channelID][i] = ...` panics with `runtime error: index out of range`. The panic occurs in a per-connection goroutine; `net/http` recovers panics in `ServeHTTP`, but this code runs after the WebSocket upgrade (`serveClient` is called from `handleWS` after `upgrader.Upgrade`), so the goroutine is no longer covered by `http.Server`'s panic recovery. An unrecovered panic terminates the entire server process.

**Exploitability:** Stale waiters should not normally accumulate because `relay`'s defer removes each connection from `waiters` on exit. However, any path that adds a connection to `waiters` but bypasses `relay`'s cleanup (e.g. a crashed/panicked relay goroutine, or a future refactor) leaves a stale entry. Once 2+ stale entries exist for one channel ID, the next `handleAllocate` for that ID panics.

**Impact — worse than a crash:** The panic occurs **while `s.mu` is held**. `handleAllocate` uses an explicit `s.mu.Unlock()` at line 306, not a `defer`, so when the panic fires inside the loop the mutex is never released. `net/http`'s per-connection panic recovery catches the panic (the handler goroutine survives), but it has no knowledge of `s.mu` and cannot unlock it. The result is a **permanent deadlock of the server's main mutex**: every subsequent `handleAllocate`, `handleJoin`, `relay` defer, `dropChannel`, and `purgeExpiredWaiters` call blocks on `s.mu` forever. The listening socket still accepts TCP/TLS connections, but every WebSocket handler hangs — the server is frozen with no crash to trigger a supervisor restart. This is strictly worse than a process crash (which a systemd/unit would restart).

The small `uint16` channel-ID space (SUM-01) makes probing for a channel that has accumulated stale waiters easier. Severity Medium-to-High in real-world effect; rated Medium because the trigger requires stale-waiter accumulation, which normal operation does not produce.

**Recommendation:** Build a survivor slice instead of mutating in place, and use a `defer` to guarantee the unlock runs even if a future panic is introduced:

```go
s.mu.Lock()
defer s.mu.Unlock()
survivors := make([]*wsConn, 0, len(s.waiters[channelID]))
for _, w := range s.waiters[channelID] {
    if w.conn == conn { survivors = append(survivors, w); continue }
    s.logger.Warn("Removing stale waiter for channel", "channel_id", channelID, "sender", w.sender)
    w.conn.Close()
}
s.waiters[channelID] = survivors
```

Note: the `defer s.mu.Unlock()` change should be applied to every `s.mu.Lock()` site in `server.go` so that no future panic in a critical section can deadlock the server. Audit all Lock/Unlock pairs in `internal/server/server.go` and convert to `defer` where the lock scope ends at the function's end or where a panic-safe unlock is desired.

**Fix applied in commit [to be committed] — `internal/server/server.go:292-308`.** Replaced the in-place swap-with-last mutation with a survivor-slice append loop. The `s.mu.Unlock()` call remains explicit (not deferred) because the lock scope does not span the entire function — a second critical section immediately follows. Survivor-slice construction is inherently panic-free: it never writes past the slice boundary and handles any number of stale entries. Regression tests added in `internal/server/server_allocate_internal_test.go` (`TestStaleWaiterCleanupNoPanic`, `TestStaleWaiterCleanupNoStaleEntries`, `TestStaleWaiterCleanupThreeStale`).

**Severity:** Medium (latent trigger, but impact is a permanent server-wide deadlock — no crash/restart).

---

#### ~~M-02: UDP reflector client does not verify the response source address~~ **FIXED**

**Location:** `internal/network/stun.go:65,83`

**Description:** `DiscoverViaReflector` reads both the phase-1 cookie response and the phase-2 address response with the source address discarded (`n, _, err := conn.ReadFrom(buf)`). The cookie is 64 bits of HMAC and is sent in clear over the wire, so an **on-path** attacker between the client and the reflector can observe the cookie and inject both a spoofed phase-1 and phase-2 response carrying an attacker-chosen external address. That address becomes `PublicEndpointV4/V6` in the peer's encrypted endpoint bundle.

**Impact:** The endpoint bundle is encrypted with the hybrid key (which the attacker does not know), and the QUIC handshake is SPKI-pinned to the peer's ephemeral cert. The attacker therefore cannot MITM the QUIC connection; the worst outcome is that hole-punching is misdirected to an attacker-controlled address, causing the QUIC dial/listen to fail. This is a **DoS / traffic-misdirection** vector, not a confidentiality or integrity breach. Off-path attackers cannot perform it (they cannot see the cookie).

**Recommendation:** Verify that each response's source `net.Addr` resolves to the same IP:port as the resolved `udpAddr` (compare `addr.(*net.UDPAddr).IP` and `.Port` against `udpAddr.IP`/`udpAddr.Port`). Drop mismatches silently.

**Fix applied in commit [to be committed] — `internal/network/stun.go`.** Added `verifyReflectorSource` helper that compares the response source address against the expected reflector IP:port. Both `ReadFrom` call sites now capture and verify the source address before processing the response body. Responses from unexpected sources return an error, and both callers (`tx.go`, `rx.go`) already handle discovery errors gracefully by falling back to the server-reported IP. Unit tests added in `internal/network/network_internal_test.go` (`TestDiscoverViaReflector_WrongSourcePhase1`, `TestDiscoverViaReflector_WrongSourcePhase2`, `TestDiscoverViaReflector_Success`).

**Severity:** Medium (on-path DoS; mitigated by endpoint-bundle encryption and SPKI pinning).

---

#### ~~M-03: Server trust lookup keyed by exact URL string — variant mismatch defeats enforcement~~ **FIXED**

**Location:** `internal/cli/server_trust.go:14`, `internal/config/config.go:238`

**Description:** `requireTrustedServer` and `PinServer` use the raw `serverURL` string as the map key. A user who runs `hermod trust wss://relay:4376` and then `hermod tx -s wss://relay:4376/ws` (or with a trailing slash, or without an explicit port) gets a "not trusted" error because the strings differ. This is **not a silent security bypass** — the failure is loud — but it creates user confusion and may push users toward disabling trust enforcement. It also means the trust guarantee is fragile across URL spellings.

**Recommendation:** Normalize to `scheme://host:port` (drop path, default port 4376, lowercase host) before both pinning and lookup. Re-pin on the canonical form so existing pins keep working after normalization.

**Severity:** Medium (reliability / UX that undermines a security control).

**Fix applied in commit [to be committed] — `internal/config/config.go`, `internal/cli/server_trust.go`, `internal/cli/trust.go`.** Added `NormalizeServerURL` in `config.go` that canonicalizes URLs to `scheme://host:port` (drops path/query, lowercases host, defaults scheme to `wss` and port to `4376`). Both `PinServer` and `SetDefaultServer` call `NormalizeServerURL` before storing; `requireTrustedServer` normalizes before lookup. `runTrust` uses the canonical form for pinning and display. Unit tests added in `internal/config/config_test.go` (`TestNormalizeServerURL_*`, `TestPinServer_NormalizesURL`, `TestSetDefaultServer_NormalizesURL`) and `internal/cli/unit_test.go` (`TestRequireTrustedServer_NormalizedLookup_*`). Existing pins created before this fix are automatically re-normalized when the user runs `hermod trust` again (re-pins on canonical key). Manually edited config.yaml entries with variant URLs will produce a "not trusted" error; re-running `hermod trust` fixes them.

---

### LOW

---

#### L-01: CPace ISK transcript omits explicit channel-ID/role domain separators

**Location:** `internal/crypto/crypto.go:149-154`

The ISK is `SHA-256(iskX || pubSender || pubReceiver)`. The channel ID and roles are bound only indirectly (channel ID + password live in the hash-to-curve DST at `hash_to_curve.go:325`; roles are bound via transcript ordering). RFC 9496 prescribes a transcript that explicitly includes the DSI, DSA, and peer identifiers. Hermod's construction is functionally secure for its fixed two-party, fixed-role protocol, but the deviation reduces defense-in-depth. Low severity; consider appending `[]byte("hermod-cpace-v1") || chanIDBytes || pubSender || pubReceiver` to the hash input.

---

#### L-02: `p256PointAdd` does not handle the additive-inverse / point-at-infinity edge case

**Location:** `internal/crypto/hash_to_curve.go:290-319`

If the two SSWU outputs `q0` and `q1` are additive inverses (`x1 == x2` and `y1 == -y2 mod p`), the function falls through to the standard addition branch and computes `inv(dx)` with `dx == 0`, panicking on division by zero. The probability is ~2^-128 and the comment asserts inputs are "always distinct non-infinity points", but there is no defensive guard. A panic here crashes the client process. Recommend handling `x1 == x2 && y1.Cmp(y2) != 0` by returning the point at infinity (or by re-deriving with a counter), eliminating the theoretical crash.

---

#### L-03: `math/big` field arithmetic is not constant-time (re-confirmed, accepted)

**Location:** `internal/crypto/hash_to_curve.go`

Re-confirms SUM-03 (won't fix). The password is SHA-256-pre-hashed via `expandMessageXMD` before any variable-time `math/big` code runs, so a timing leak would expose information about the hash output, not the password. Combined with network jitter (TLS, WebSocket framing), no practical exploit path exists. The rationale in `docs/audits/2026-06-07-summary.md` remains valid.

---

#### L-04: Hole-punch self-reflection can return the peer's own external address

**Location:** `internal/network/network.go:285-289`

When a peer receives a probe whose `nonce[0:7]` matches its own probe discriminator, it sends an ack and immediately returns success with `pkt.addr` as the peer address. If a NAT reflects the peer's own probe back to it, the peer treats its own external address as the peer's and attempts a QUIC dial to itself. The SPKI pin fails (own cert vs expected peer cert), so this is a **self-DoS / wasted attempt**, not a breach. Recommend discarding probes whose source address matches any of the local candidate addresses before accepting.

---

#### L-05: Rate-limiter bucket map has no hard cap (re-confirmed, open)

**Location:** `internal/server/ratelimit.go`

Re-confirms SUM-04 (open). The `buckets` map grows per distinct HMAC-hashed IP prefix; cleanup runs every 10 minutes with a 30-minute staleness threshold, and daily salt rotation clears everything. Between cycles, a botnet with many IPv6 /64s can create many ~88-byte entries. Bounded but not capped. Add an LRU cap (e.g. 100k buckets) with eviction of the least-recently-seen entry on insert.

---

#### ~~L-06: `SafeDestinationPath` silently overwrites after 9,999 collisions~~ **FIXED**

**Location:** `pkg/transfer/transfer.go:83-104`

Re-confirms SUM-07 (open). After 9,999 numbered candidates exist, the loop exits and returns `filename(9999)` without an existence check, silently overwriting. Pathological in practice.

**Fix applied in commit [to be committed] — `pkg/transfer/transfer.go`.** Changed `SafeDestinationPath` return type from `string` to `(string, error)`. Added a final `os.Stat` after the loop that returns an error if the 9,999th candidate exists. Caller updated in `internal/cli/rx.go:578`. Unit tests added in `pkg/transfer/transfer_test.go` (`TestSafeDestinationPathAllCollisions`). All existing tests updated for new signature.

---

#### ~~L-07: `dropChannel` race window for channel-ID reuse~~ **FIXED**

**Location:** `internal/server/server.go:555-571`

Re-confirms SUM-09 (open). `DeleteChannel` is called after `s.mu.Unlock()`, so a new allocation with the same ID in the microsecond gap can be deleted by the deferred `DeleteChannel`.

**Fix applied in commit [to be committed] — `internal/server/server.go`.** Moved `s.store.DeleteChannel(channelID)` inside `s.mu` (before `s.mu.Unlock()`), eliminating the race window. Unit test added in `internal/server/server_allocate_internal_test.go` (`TestDropChannelReleasesStoreEntry`).

---

#### ~~L-08: Relay error text leaks CPace failure-counter state~~ **FIXED**

**Location:** `internal/server/server.go:516-521`

Re-confirms SUM-05 (open). The relay sends `"unexpected message type: channel terminated"` vs `"unexpected message type"` depending on whether the failure threshold was reached, letting a client infer prior failures on the channel.

**Fix applied in commit [to be committed] — `internal/server/server.go`.** Unified both branches to send `"unexpected message type"` regardless of whether the failure limit was reached. Both branches call `recordFailureAndDrop` and then send the identical generic message. Unit test added in `internal/server/server_allocate_internal_test.go` (`TestRelayErrorGenericMessage`).

---

#### L-09: UDP mux silently drops packets when channel buffer is full (re-confirmed, open)

**Location:** `internal/network/network.go:62-71`

Re-confirms SUM-06 (open). Non-blocking sends with `default:` drop silently when `quicCh` (256) or `probeCh` (64) is full. QUIC retransmission and the 200 ms probe retry mask the impact, but silent drops complicate diagnosis. Add a debug-level log on drop and consider larger buffers.

---

#### ~~L-10: `serve` panics on empty `--listen` / `HERMOD_LISTEN`~~ **FIXED**

**Location:** `internal/cli/serve.go:60-63`

`if listenAddr[0] == ':'` indexes byte 0 without a length check. `hermod serve --listen ""` (or `HERMOD_LISTEN=""`) panics with index out of range. Minor input-validation gap.

**Fix applied in commit [to be committed] — `internal/cli/serve.go`.** Added `len(listenAddr) > 0 &&` guard to both the IPv4 and IPv6 override conditions. Unit tests added in `internal/cli/unit_test.go` (`TestServeListenAddrOverrideEmptyListenV4`, `TestServeListenAddrOverrideEmptyListenV6`).

---

#### L-11: Server private key stored unencrypted in config.yaml (re-confirmed, accepted)

**Location:** `internal/config/config.go:173,99`

Re-confirms SUM-02 (accepted). The ECDSA P-256 private key is stored as PEM in `~/.config/hermod/config.yaml` (file `0o600`, dir `0o700`). Any same-user process or backup/indexing tool can read it. Accepted trade-off for the intended ephemeral, single-host usage; the key regenerates if missing and never leaves the machine. Documented in the project security model.

---

#### L-12: `CipherSuites` TLS config field is ineffective for TLS 1.3

**Location:** `internal/config/config.go:141`

`BuildTLSConfig` populates `CipherSuites` from config, but Go's `crypto/tls` ignores this field for TLS 1.3 connections (it only affects TLS 1.0–1.2). Because `MinVersion` is TLS 1.3, the configured `TLS_AES_256_GCM_SHA384` / `TLS_CHACHA20_POLY1305_SHA256` entries never apply. Not a vulnerability — all TLS 1.3 AEAD suites are secure — but it is dead config that may mislead operators into thinking they have enforced a cipher policy. The post-quantum property is carried by `CurvePreferences` (`X25519MLKEM768`), which *is* effective. Recommend documenting that only `CurvePreferences` is operative for TLS 1.3.

---

#### L-13: `DecodeExternalAddress` returns `net.IP` slices aliasing the caller's buffer

**Location:** `internal/server/udp_reflect.go:242,249`

`net.IP(data[1:5])` and `net.IP(data[1:17])` reference the input slice rather than copying. If a future refactor reuses the read buffer across calls, the returned `UDPAddr.IP` would be silently corrupted. Current callers (`stun.go:88`) use a local buffer that is not reused after the call, so there is no live bug, but the aliasing is a latent footgun. Recommend copying: `ip := append(net.IP(nil), data[1:5]...)`.

---

#### L-14: Channel ID is client-chosen and unauthenticated on `Allocate`

**Location:** `internal/server/server.go:285`, `internal/crypto/crypto.go:715`

The sender generates the channel ID and the server accepts any unused `uint16`. This is by design (the ID is encoded in the transfer code; security comes from the CPace password). Combined with the small uint16 space (SUM-01), an attacker can target specific IDs. The per-IP cap (100) and rate limiter (5/s per IP) bound abuse. Re-confirming the design rationale; no change recommended beyond SUM-01's existing discussion.

---

## Re-confirmation summary

| Prior ID | Status | This audit |
|----------|--------|------------|
| SUM-01 (channel ID space) | Won't fix | Re-confirmed; see L-14 |
| SUM-02 (server key in YAML) | Accepted | Re-confirmed; see L-11 |
| SUM-03 (math/big timing) | Won't fix | Re-confirmed; see L-03 |
| SUM-04 (rate limiter cap) | Open | Re-confirmed; see L-05 |
| SUM-05 (error info leak) | Fixed | FIXED; see L-08 |
| SUM-07 (file overwrite) | Fixed | FIXED; see L-06 |
| SUM-09 (dropChannel race) | Fixed | FIXED; see L-07 |

---

## Verification performed

- `go build ./...` — clean.
- `go vet ./...` — clean.
- `go test -count=1 ./internal/... ./pkg/...` — all packages pass.
- `govulncheck` — not usable in this environment (internal error on `golang.org/x/sys` import via `go-isatty`); manual dependency review of `go.mod` found only pinned, stable versions (`gorilla/websocket v1.5.3`, `quic-go v0.59.1`, `cobra v1.10.2`, `yaml.v3 v3.0.1`).

---

## Recommended remediation priority

1. ~~**M-01** — fix the stale-waiter loop to prevent a server-crash DoS. One function rewrite.~~ **FIXED**
2. ~~**M-02** — verify UDP reflector response source address. A few lines in `stun.go`.~~ **FIXED**
3. ~~**M-03** — normalize server URL before trust lookup/pin. Small helper in `internal/config`.~~ **FIXED**
4. ~~**L-07** — move `DeleteChannel` inside the lock (one line; closes SUM-09).~~ **FIXED**
5. ~~**L-08** — unify relay error strings (one line; closes SUM-05).~~ **FIXED**
6. ~~**L-06** — add a final existence check in `SafeDestinationPath` (closes SUM-07).~~ **FIXED**
7. ~~**L-10** — guard empty `--listen` (one line).~~ **FIXED**
8. **L-02** — handle additive-inverse edge case in `p256PointAdd` (defense-in-depth).
9. **L-04**, **L-05**, **L-09**, **L-13** — hardening items.

All remaining items are accepted design choices or previously documented open trade-offs.
