# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.19.1] - 2026-06-12

- **why:** Make X25519MLKEM768 the only default TLS curve for full post-quantum security; document quantum-safety claims in README
- **model:** opencode/deepseek-v4-flash
- **tags:** security, crypto, post-quantum, mlkem, tls

### Changed

- Default TLS curve preferences reduced to `["X25519MLKEM768"]` only — removes `X25519` and `CurveP256` fallbacks so every connection uses post-quantum hybrid key exchange (`internal/config/config.go`)
- `BLUEPRINT.md`, `CONTEXT.md`, `PROJECT.md`, and `README.md` updated to document the PQ-only curve default

### Added

- Post-quantum security claim in README — documents that all channels use X25519MLKEM768 exclusively with no classical-only fallback

### Security

- All TLS connections now exclusively use X25519MLKEM768 (FIPS 203) hybrid key exchange — no classical-only fallback means an attacker with a quantum computer cannot decrypt recorded traffic without also breaking ML-KEM-768

## [v0.19.0] - 2026-06-12

- **why:** Switch from certificate DER pinning to SPKI (public key) pinning so certificate renewal with the same key does not break client trust; add automatic certificate renewal 14 days before expiry with key reuse
- **model:** opencode/deepseek-v4-flash
- **tags:** security, crypto, spki, pinning, certificate, auto-renewal

### Added

- `PubKeyFingerprint()` in `internal/network/network.go` and `internal/config/config.go` — computes SHA-256 of the Subject Public Key Info instead of the certificate DER, so the fingerprint survives certificate renewal with the same key pair
- `RenewServerCert()` in `internal/config/config.go` — creates a new self-signed certificate that reuses the existing private key, keeping the SPKI fingerprint unchanged
- Certificate auto-renewal: `hermod serve` automatically renews the certificate 14 days before the current one expires, reusing the existing key — clients never need to re-pin after automatic renewal (`internal/cli/serve.go`)
- `TestRunServe_AutoRenewCert` — verifies auto-renewal extends `NotAfter` while the SPKI fingerprint stays identical (`internal/cli/unit_test.go`)
- `TestPubKeyFingerprint` and `TestPubKeyFingerprint_Invalid` in both `internal/network/network_test.go` and `internal/config/config_test.go`

### Changed

- All certificate trust verification switched from certificate DER hash to SPKI (Subject Public Key Info) hash: `makeCertPinner`, `dialSignaling`, `FetchServerFingerprint` (`internal/network/network.go`, `internal/network/signaling.go`)
- `EndpointBundle.CertFingerprint` renamed to `EndpointBundle.PubKeyFingerprint` with JSON tag `public_key_fingerprint` (`internal/network/handshake.go`; all callers updated across 15 files)
- Server startup now prints "Server public key fingerprint" instead of "Server fingerprint" (`internal/cli/serve.go`)
- `hermod trust` help text updated to describe SPKI pinning and its benefit during key-renewal (`internal/cli/trust.go`)
- Fingerprint mismatch error messages rewritten with clear next steps — tell the user to verify the transfer code or run `hermod trust` to re-pin, instead of dumping hex values (`internal/network/network.go`, `internal/network/signaling.go`)
- `BLUEPRINT.md` and `CONTEXT.md` updated to document SPKI pinning, auto-renewal, and key-reuse behavior

### Security

- Certificate auto-renewal reuses the existing private key — the SPKI fingerprint stays the same, so clients that pinned the server's public key continue to trust it without manual intervention

## [v0.18.0] - 2026-06-12

- **why:** Add CGNAT UDP reflection for NAT traversal, remove dead code and legacy protocol compat, add lint checks to test suite, fix data races, document IPv4/IPv6 serve caveats
- **model:** opencode/deepseek-v4-flash
- **tags:** network, cgnat, stun, cleanup, testing, docs

### Added

- CGNAT address discovery via server UDP reflection with two-phase HMAC cookie handshake — detects external UDP address before endpoint bundle exchange, critical for Carrier-Grade NAT where UDP port differs from WebSocket TCP port (`internal/server/udp_reflect.go`, `internal/network/stun.go`)
- `DiscoverViaReflector()` client function to perform the cookie handshake, with fallback to server-reported WebSocket IP + local port on failure (`internal/network/stun.go`)
- `lint_test.go` — runs `deadcode` and `staticcheck` (U1000) as part of `go test ./...`, skippable via `HERMOD_SKIP_LINT`
- Re-exposed `DialQUIC()` and `ListenQUIC()` as exported API for direct use by tx/rx (replacing internal `RaceQUIC`)

### Changed

- `-4`/`-6` flag descriptions updated from "Use IPv4/IPv6 only for hole punching" to "Restrict to IPv4/IPv6 only for listen address, signaling connection, and hole punching" — accurate for all subcommands (`internal/cli/root.go`)
- IPv4/IPv6 caveats documented in README under `serve`: `-6` does not isolate to IPv6 on default Linux (`IPV6_V6ONLY=0`); explicit `--listen` silently ignores `-4`/`-6`; cross-subcommand effect clarified
- All log and user-facing messages reviewed for clear language: removed internal jargon ("cookie req", "SHA-256 mismatch", "sender hash"), removed `[CERT EXPIRY]` prefix noise, fixed inconsistent casing in `logWarn` calls, replaced `"day(s)"` with `"days"` in cert expiry warnings, clarified error messages with next steps (`internal/cli/rx.go`, `internal/cli/tx.go`, `internal/cli/serve.go`, `internal/server/server.go`, `internal/server/udp_reflect.go`, `internal/server/ratelimit.go`, `internal/config/config.go`, `pkg/transfer/transfer.go`)

### Removed

- Dead methods: `CPaceSession.SharedK()`, `CPaceSession.PubMessage()`, `X25519PubBytes()` (`internal/crypto/crypto.go`)
- Dead variable `p256Two` (`internal/crypto/hash_to_curve.go`)
- Dead STUN code: `DiscoverExternalAddress()`, `parseSTUNResponse()`, `parseXORMappedAddress()`, `xorMagicIP()`, `xorMagicPort()`, `decodeXORMappedAddress()`, `DefaultSTUNServer`, `ReflectRequest`, `stunTXID` type, and all STUN protocol constants (`internal/network/stun.go`)
- Dead method `Server.Addr()` (`internal/server/server.go`)
- Dead types `quicConnectionState` and `jsonPayload` (`internal/cli/tx.go`)
- Legacy UDP reflection `0x00` single-byte probe handler — all clients now use the cookie protocol (`internal/server/udp_reflect.go`)
- Legacy direct-address response parsing in `DiscoverViaReflector` — all servers now use the cookie protocol (`internal/network/stun.go`)

### Fixed

- Data races in e2e and unit tests resolved (concurrent map writes, shared state in `ExecuteArgs`)
- quic-go UDP buffer size warnings silenced by delegating `SetReadBuffer`/`SetWriteBuffer` in `muxedConn`

## [v0.17.1] - 2026-06-11

- **why:** Apply clear-language fixes to all user-facing strings and log messages
- **model:** opencode/deepseek-v4-flash
- **tags:** docs, clear-language, error-messages

### Changed

- SAS verification error messages in `performSASCoordinatedWith` now use lowercase for wrapped fmt.Errorf calls, consistent with Go wrapping convention (`internal/cli/tx.go`)
- Signaling server "unrecognized message type" WebSocket error changed to "first message must be 'allocate' or 'join'" — tells the caller what types are accepted (`internal/server/server.go`)
- Test assertions updated to match lowercase error substrings (`internal/cli/sas_test.go`)

## [v0.17.0] - 2026-06-11

- **why:** Add hybrid KEM encryption (X25519 + ML-KEM-768 + CPace) for endpoint bundles exchanged over signaling relay, providing post-quantum security for the handshake phase
- **model:** opencode/deepseek-v4-flash
- **tags:** crypto, kem, post-quantum, mlkem, security

### Added

- `GenerateX25519KeyPair()`, `ECDHX25519()`, `GenerateMLKEMReceiverKey()`, `EncapsulateMLKEM()`, `DecapsulateMLKEM()`, `DeriveHybridBlobKey()` — three-pillar hybrid KEM using CPace (P-256) + X25519 ECDH + ML-KEM-768 (`crypto/mlkem` stdlib). Hybrid key = SHA-256(kClassical || ssX25519 || ssMLKEM) (`internal/crypto/crypto.go`)
- Binary blob serialization: `SenderHandshakeBlob`, `ParseSenderHandshakeBlob`, `ReceiverHandshakeBlob`, `ParseReceiverHandshakeBlob`, `SenderBundleBlob`, `ParseSenderBundleBlob` — fixed-length encoding for CPace points, X25519 keys, ML-KEM encapsulation keys, and ciphertexts (`internal/network/handshake.go`)
- Verification chain table in `docs/protocol.md` documenting all 9 verification layers from CPace through trailing SHA-256 hash
- Unit tests for hybrid KEM key generation, ECDH, ML-KEM round-trip, hybrid key derivation, and end-to-end sender-receiver exchange (`internal/crypto/crypto_test.go`)
- Unit tests for handshake blob serialization round-trips and error paths (`internal/network/network_test.go`)

### Changed

- Endpoint bundle encryption now uses `hybridKey` instead of `kClassical` directly. Sender and receiver exchange X25519 public keys + ML-KEM encapsulation keys alongside CPace points in binary format (2 blobs), then exchange KEM ciphertext + encrypted bundles (2 blobs) — still 4 blobs total (`internal/cli/tx.go`, `internal/cli/rx.go`)
- Hole punch nonce now derived from `hybridKey` (CPace + X25519 + ML-KEM-768) instead of `kClassical` alone — consistent with using the strongest session key material (`internal/cli/tx.go`, `internal/cli/rx.go`)
- All e2e tests updated to use hybrid KEM flow instead of CPace-only exchange (`e2e/integration_test.go`, `e2e/verify_negotiation_test.go`)
- `BLUEPRINT.md` and `CONTEXT.md` updated with hybrid KEM architecture and dependency notes
- `docs/api.md` updated with hybrid KEM function signatures, blob serialisation API, replaced obsolete CPaceMsg section, updated HolePunch nonce doc
- `README.md` step 5 and security table updated to mention post-quantum hybrid KEM

### Removed

- Old CPace-only endpoint bundle encryption (AES-256-GCM with kClassical only) — wire protocol is now hybrid-only, no backward compatibility

## [v0.16.2] - 2026-06-11

- **why:** Resolve security audit findings from gpt-5.4 — expired channel cleanup, client-side WebSocket read limit, trailing hash fail-closed, ws:// rejection, and SAS defense-in-depth
- **model:** opencode/deepseek-v4-flash
- **tags:** security, server, network, integrity, cleanup

### Fixed

- Expired channels now close live WebSocket waiters and remove stale entries — `purgeExpiredWaiters()` runs after each GC tick, `handleAllocate()` rejects stale waiters, WebSocket read deadline + pong handler closes idle connections (`internal/server/server.go`, `internal/server/store.go`)
- Client sets `conn.SetReadLimit(64 KiB)` in `dialSignaling()` and validates decoded `Payload` size in `Recv()` — prevents memory exhaustion from a compromised relay (`internal/network/signaling.go`)
- Trailing hash verification is now fail-closed — missing or unreadable hash is a fatal error, temp file is not renamed until verification passes, received byte count checked against `meta.Size` (`internal/cli/rx.go`, `pkg/transfer/transfer.go`)
- `dialSignaling()` and `runTrust()` reject `ws://` URLs with an error instead of a warning — plaintext mode removed (`internal/network/signaling.go`, `internal/cli/trust.go`)
- `SASFromBytes()` biased modulo fallback replaced with `panic` — path is unreachable (callers always supply ≥32 bytes) (`internal/crypto/crypto.go`)

### Changed

- Removed all audit document cross-references (e.g. `(H-01)`, `(M-07)`) from code comments across `internal/cli/`, `internal/config/`, `internal/crypto/`, `internal/network/`, `internal/server/`, and `pkg/transfer/` — comments now explain intent directly without external references

## [v0.16.1] - 2026-06-11

- **why:** Resolve security audit findings (H1–H5, M1–M5, L1–L5) — HTTP timeouts, constant-time ECDH, RFC 9380 DST compliance, concurrent write safety, context propagation, and defense-in-depth hardening
- **model:** opencode/deepseek-v4-flash
- **tags:** security, audit, crypto, network, server

### Security

- **H1:** Added `ReadHeaderTimeout=10s`, `ReadTimeout=30s`, `WriteTimeout=30s`, `IdleTimeout=120s` to HTTP server — prevents Slowloris DoS (`internal/server/server.go`)
- **H2:** Replaced deprecated `crypto/elliptic.ScalarMult` with `crypto/ecdh.P256()` — constant-time scalar multiplication using stdlib only (`internal/crypto/crypto.go`)
- **H3:** Replaced DST truncation with SHA-256("H2C-OVERSIZE-DST-" \|\| DST) per RFC 9380 §3.1 — fixes collision on passwords >236 bytes (`internal/crypto/hash_to_curve.go`)
- **H4:** Moved `WriteJSON` inside mutex in `dropChannel` — prevents Gorilla WebSocket panic on concurrent writes (`internal/server/server.go`)

### Changed

- **M1:** `DialSignaling`, `DialSignalingWithFamily`, `FetchServerFingerprint` now accept `ctx context.Context` — SIGINT cancels in-progress dials. `HandshakeTimeout` set to 15s (`internal/network/signaling.go`; updated all callers)
- **M3:** `DialContext` callbacks use `net.Dialer{}.DialContext(ctx, ...)` instead of `net.Dial(...)` — context cancellation propagates to TCP dial (`internal/network/signaling.go`)
- **M4:** Temp files created with `0o600` + `O_EXCL` instead of `os.Create` — prevents world-readable temp files and silent truncation of stale temps (`internal/cli/rx.go`)
- **M5:** Warning logged when `ws://` scheme is used — alerts user to unencrypted signaling (`internal/network/signaling.go`)
- **L1:** KindText input redacted to `<redacted>` in debug logs — prevents secret leakage via stderr (`internal/cli/tx.go`)
- **L2:** Added `readLenPrefixedMax()` with 256-byte limit for trailing hash stream — prevents 1 MiB allocation on corrupt input (`internal/cli/rx.go`)
- **L3:** Ephemeral QUIC cert `NotAfter` reduced from 24h to 2h — limits exposure window on leaked key (`internal/cli/tx.go`)
- **L4:** Windows config path uses `os.UserConfigDir()` instead of `os.Getenv("APPDATA")` — handles unset/tampered `APPDATA` gracefully (`internal/config/config.go`)
- **L5:** `writeError` logs failures at `slog.Debug` instead of silent discard (`internal/server/server.go`)
- Hole punch error messages made actionable: include candidate counts, address family, and timeout info instead of redundant "UDP hole punch" repetition (`internal/network/network.go`, `internal/cli/tx.go`, `internal/cli/rx.go`)

### Removed

- **SUM-10:** Deleted five stale `TestSQLiteStore*` functions — relics from the removed SQLite backend; `TestMemoryStore*` already covers the same paths (`internal/server/server_test.go`)

### Documentation

- Updated `DialSignaling`, `DialSignalingWithFamily`, `FetchServerFingerprint` signatures in `docs/api.md` to include `ctx context.Context`
- Tagged all 10 consolidated audit findings as `[OPEN]` / `[CLOSED]` / `[WON'T FIX]` in `docs/audits/2026-06-07-summary.md`
- Moved audit report to `docs/audits/audit-sonnet-4-6-2026-06-11.md`
- Updated `BLUEPRINT.md` version, `CONTEXT.md` and `README.md` Windows config path notes
- Documented SUM-01 (channel ID space), SUM-03 (hash-to-curve timing) as accepted design decisions with rationale

## [v0.16.0] - 2026-06-10

- **why:** Enable bidirectional QUIC initiation so the P2P connection succeeds even when only one direction traverses the NAT
- **model:** opencode/deepseek-v4-flash
- **tags:** network, quic, bidirectional, holepunch, nat

### Added

- `RaceQUIC()` — races a QUIC dial and accept simultaneously on the same muxed UDP socket; returns whichever handshake completes first. Adds random jitter (0-100ms via `crypto/rand`) to the dial to break symmetry on loopback (`internal/network/network.go`)
- ASCII art connection flow diagram in protocol doc covering all 6 phases from signaling through payload transfer (`docs/protocol.md`)

### Changed

- `tx` and `rx` both call `RaceQUIC` after hole punch, replacing the previous sender-always-dials / receiver-always-listens design (`internal/cli/tx.go`, `internal/cli/rx.go`)
- `docs/protocol.md` QUIC connection section updated to document bidirectional race and mutual TLS (`RequireAnyClientCert`)
- `docs/api.md` — added `RaceQUIC` entry; removed `DialQUIC` / `ListenQUIC` entries

### Removed

- `DialQUIC` and `ListenQUIC` functions from `internal/network/network.go` — all callers now use `RaceQUIC`
- `TestDialAndListenQUIC` replaced with `TestRaceQUIC` (`internal/network/network_internal_test.go`)
- All e2e test references to `DialQUIC`/`ListenQUIC` migrated to `RaceQUIC` (`e2e/integration_test.go`, `e2e/verify_negotiation_test.go`)

### Fixed

- All doc references to "RSA-2048 ephemeral certificates" corrected to ECDSA P-256, matching the production code (`docs/protocol.md`, `docs/api.md`)

## [v0.15.0] - 2026-06-10

- **why:** Replace PGP word lists with EFF Short Wordlist 1 for SAS generation; fix modulo bias; add e2e SAS cross-check
- **model:** opencode/deepseek-v4-flash-free
- **tags:** sas, crypto, security, wordlist, refactor

### Changed

- `SASFromBytes` now draws 6 words from the EFF Short Wordlist 1 (1296 entries) using rejection sampling on key material bytes, producing deterministic output with no modulo bias (`internal/crypto/crypto.go`)

### Removed

- `pgpWordListEven` and `pgpWordListOdd` constants (256 entries each) from `internal/crypto/crypto.go`
- `SASString` helper function — inlined `strings.Join` at the single call site in `internal/cli/tx.go`

### Added

- `TestSASDeterministic` and `TestSASDifferentInput` unit tests (`internal/crypto/crypto_test.go`)
- E2E SAS word cross-check in `TestVerifyNegotiation` — validates both sides of a QUIC connection derive identical 6-word SAS (`e2e/verify_negotiation_test.go`)

## [v0.14.3] - 2026-06-10

- **why:** Apply plain language to CLI error messages — capitalize, punctuate, use active voice
- **model:** opencode/deepseek-v4-flash-free
- **tags:** cli, ux, error-messages, clear-language

### Changed

- Cancel messages use active voice: "You cancelled" instead of "cancelled by user", "The other side cancelled" instead of "the other side cancelled" (`internal/cli/cancel.go`, `internal/cli/tx.go`, `internal/cli/rx.go`)
- All user-facing error messages in `tx`, `rx`, and `cancel` now start with a capital letter and end with a period (`internal/cli/tx.go`, `internal/cli/rx.go`, `internal/cli/cancel.go`)

### Fixed

- SAS error messages: "received SAS_OK but got no answer" now reads as proper sentence (`internal/cli/sas_test.go`)
- Unit tests updated to match new message format (`internal/cli/cancel_test.go`, `internal/cli/tx_unit_test.go`, `internal/cli/unit_test.go`)

## [v0.14.2] - 2026-06-10

- **why:** Fix flaky integration tests by eliminating WebSocket relay race conditions; reach ≥80% coverage across all packages
- **model:** opencode/deepseek-v4-flash-free
- **tags:** server, signaling, race-condition, websocket, tests, coverage

### Fixed

- `handleJoin` wrote `MsgOK` to the receiver after adding it to `waiters`, letting the sender's relay forward a `MsgBlob` before `MsgOK` — receiver's `Join()` failed, receiver disconnected, relay closed sender's connection with WebSocket close 1006 (`internal/server/server.go`)
- `handleAllocate` and `handleJoin` wrote `WriteJSON` after releasing `s.mu`, causing gorilla websocket concurrent-write panics (`internal/server/server.go`)
- Relay defer did not close the peer's WebSocket on disconnect, leaving the peer's `ReadJSON` stuck forever (`internal/server/server.go`)
- Port-reuse TOCTOU race in test helpers: `Listen(":0")` → `Close()` → `Serve(port)` could reuse a freed port (`internal/server/server.go`, `internal/network/signaling_test.go`)
- Transfer code printed before `Allocate()` completed, allowing the receiver to join a non-existent channel (`internal/cli/tx.go`)
- Package-level globals (`quietMode`, `ipv4Only`, `ipv6Only`) leaked between tests via `testscript` subprocesses and `ExecuteArgs` (`internal/cli/transfer_integration_test.go`)
- Debug logging calls (`logf`, `logBlob`) left in `server.go` and `signaling.go` from earlier diagnosis

### Added

- `join-rate` and `join-burst` server flags for independent join rate limiting
- Tests for `newStreamBar`, `barHumanizeBytes`, `cancelMessage`, `newHashBar`, `openTTY` (`internal/cli/stream_bar_test.go`, `internal/cli/tx_unit_test.go`, `internal/cli/tty_unix_test.go`)
- Tests for `CertExpiryInfo` and `LogCertExpiry` (`internal/config/cert_expiry_test.go`)
- `internal/cli` now at 80.0%, `internal/config` at 88.2% coverage

### Removed

- File-based debug logging (`/tmp/hermod_*.log`) from `server.go` and `signaling.go`

## [v0.14.1] - 2026-06-08

- **why:** Increase hole-punch probe packet size from 3 to 8 bytes for 64-bit entropy and firewall/DDPI resilience
- **model:** opencode/deepseek-v4-flash-free
- **tags:** network, holepunch, security, crypto

### Changed

- `holePunchNonce()` now returns the full 32-byte SHA-256 hash instead of only 4 bytes (`internal/cli/tx.go`)
- `HolePunch()` and `HolePunchDual()` accept `[32]byte` nonce; probe/ack payloads are now 8 bytes each (marker + 7 hash bytes) instead of 3 bytes (`internal/network/network.go`)
- Probe and ack verification uses `subtle.ConstantTimeCompare` for timing-safe comparison of all 7 hash bytes (`internal/network/network.go`)
- Minimum probe packet length for acceptance raised from 3 to 8 bytes (`internal/network/network.go`)

## [v0.14.0] - 2026-06-08

- **why:** Add -4/-6 IP family enforcement to serve and trust commands, completing the feature across all subcommands
- **model:** opencode/deepseek-v4-flash
- **tags:** cli, ipv4, ipv6, serve, trust

### Added

- `serve` command now respects `-4`/`-6` flags: address `:PORT` (dual-stack) is overridden to `0.0.0.0:PORT` (IPv4-only) or `[::]:PORT` (IPv6-only) (`internal/cli/serve.go`)
- `trust` command now respects `-4`/`-6` flags: TLS certificate fetch is restricted to the specified IP family (`internal/cli/trust.go`, `internal/network/signaling.go`)
- Unit tests for serve `-4`/`-6` flag propagation and listen address override logic (`internal/cli/unit_test.go`)

## [v0.13.0] - 2026-06-08

- **why:** Improve hole-punch reliability with persistent probes past QUIC handshake; enforce strict IP family isolation for -4/-6 flags; fix IPv6 zone ID handling in signaling
- **model:** opencode/deepseek-v4-flash
- **tags:** network, holepunch, ipv6, cli, signaling, reliability

### Added

- Signaling server WebSocket connection now respects `-4`/`-6` flags, using `tcp4` or `tcp6` at the transport level (`internal/cli/tx.go`, `internal/cli/rx.go`, `internal/network/signaling.go`)
- Strict IP family isolation: `-4` filters IPv6 peer candidates and binds `0.0.0.0:0`; `-6` filters IPv4 candidates and binds `[::]:0` (`internal/cli/tx.go`, `internal/cli/rx.go`)

### Fixed

- Hole-punch probes now stay alive until QUIC handshake completes, preventing connection failures from short-lived NAT mappings when one side stops probing before the other receives a probe (`internal/network/network.go`, `internal/cli/tx.go`, `internal/cli/rx.go`)
- Signaling server now populates both `public_ipv4` and `public_ipv6` in responses and strips IPv6 zone IDs (e.g. `%eth0`) before parsing; JSON unmarshal errors are now returned instead of silently dropped (`internal/server/server.go`, `internal/network/handshake.go`, `internal/network/signaling.go`)

### Changed

- README updated with global flags section, missing `--quiet`/`--version` flags, trust subcommand reference, Norse mythology name origin, and Magic Wormhole inspiration (`README.md`)
- `tasks/` directory cleaned up — completed task files moved to `tasks/done/`

## [v0.12.1] - 2026-06-07

- **why:** Consolidate three audit reports into one self-contained summary; fix TLS fingerprint verification and rate limiter isolation
- **model:** opencode/deepseek-v4-flash
- **tags:** audit, security, trust, ratelimit

### Fixed

- TLS fingerprint now verified during handshake (not after) when `--fingerprint` is supplied to `hermod trust` (`internal/network/signaling.go`, `internal/cli/trust.go`)
- Rate limiter split into per-endpoint instances (`certRL`, `wsRL`, `joinRL`) so `/cert` abuse cannot starve WebSocket connections (`internal/server/server.go`, `internal/server/ratelimit.go`)
- Channel enumeration closed: all join failures now return generic `"operation failed"` error instead of revealing whether the channel exists (`internal/server/server.go`)
- Authored by deepseek-v4-flash, deepseek-v4, and claude-sonnet-4-6

### Changed

- Consolidated three audit reports (`docs/audits/`) into a single self-contained summary with deduplicated findings, proposed mitigations, and a new `SUM-NN` numbering scheme
- Removed obsolete audit files

## [v0.12.0] - 2026-06-07

- **why:** Add dual-stack IPv4/IPv6 support to NAT hole punching with IPv6 preference, IPv4 fallback, and `-4`/`-6` enforcement flags
- **model:** opencode/deepseek-v4-flash
- **tags:** network, holepunch, ipv6, dual-stack, cli

### Added

- `HolePunchDual()` — two-phase NAT hole punching: IPv6 first (5 s timeout), then IPv4 fallback (remaining context timeout) (`internal/network/network.go`)
- `IPFamily` type (`Any`/`V4`/`V6`) for filtering local address collection (`internal/network/handshake.go`)
- `SplitPublicIP()` — classifies a bare IP string into the correct address family's `host:port` format (`internal/network/handshake.go`)
- `EndpointBundle.CandidatesV4()` / `CandidatesV6()` — extract candidate lists by address family (`internal/network/handshake.go`)
- `-4`/`--ipv4` and `-6`/`--ipv6` persistent flags, mutually exclusive, enforce a single IP protocol for hole punching (`internal/cli/root.go`)
- Signaling server response now includes `public_ipv4` or `public_ipv6` key alongside `public_ip` (`internal/server/server.go`)

### Changed

- `EndpointBundle` now carries separate `LocalEndpointsV4/V6` and `PublicEndpointV4/V6` fields — legacy monomorphic fields removed (`internal/network/handshake.go`)
- `LocalEndpoints()` now returns split v4/v6 slices and accepts an `IPFamily` filter (`internal/network/handshake.go`)
- `Allocate()` and `Join()` return both IPv4 and IPv6 public addresses (`internal/network/signaling.go`)
- `tx` and `rx` use dual-stack bundle exchange and two-phase holepunch (`internal/cli/tx.go`, `internal/cli/rx.go`)
- Signaling server default listen address changed from `0.0.0.0:4376` (IPv4-only) to `:4376` (dual-stack) (`internal/cli/serve.go`)

### Removed

- Backward compatibility fields `PublicEndpoint` and `LocalEndpoints` from `EndpointBundle` — development-phase code, no migration needed

## [v0.11.0] - 2026-06-07

- **why:** Apply plain language to all user-facing text, fix SAS prompt and progress bar UX issues, and add port 4376 fallback to `hermod trust`
- **model:** opencode/deepseek-v4-flash
- **tags:** cli, ux, sas, progress-bar, clear-language, trust

### Added

- `hermod trust` now defaults to port 4376 when no port is specified in the server URL (`internal/cli/trust.go`)

### Changed

- Progress bar style: file bar from hash/pipes (`|##########.....|`) to equals/brackets (`[==========-----]`), stream bar from dots/hash (`|..###..........|`) to arrows/brackets (`[--<=>----------]`) (`internal/cli/stream_bar.go`, `internal/cli/tx.go`)
- All user-facing strings rewritten to ISO 24495-1:2023 plain language: expanded abbreviations (cpace → CPace, udp → UDP, quic → QUIC, recv → receive), added specific error causes, and replaced generic errors with clear next steps (20 files across cli, crypto, network, server, transfer)

### Fixed

- SAS verification: add missing newline after identicon output in `tx.go`
- SAS prompt: detect context cancellation when scanner unblocks before `ctx.Done()` fires, preventing a hung prompt (`internal/cli/tx.go`)
- SAS error: add newline before error message so receiver cancellation appears on its own line, not appended to prompt text
- SAS error messages: distinguish "cancelled by you" from "cancelled by the other side" using plain language
- `rx KindStream` output: remove extra blank line after piped stdin transfers (`internal/cli/rx.go`)
- SAS test: expand coverage for cancellation race and plain-language error assertions (`internal/cli/sas_test.go`, `internal/cli/unit_test.go`)

## [v0.10.4] - 2026-06-07

- **why:** Add GitHub Actions release workflow for automated cross-platform builds and publishing
- **model:** opencode/deepseek-v4-flash
- **tags:** ci, release, build, github-actions

### Added

- `.github/workflows/release.yml` — GitHub Actions workflow triggered on patch tag push; builds for linux/amd64, linux/arm64, windows/amd64, windows/arm64, darwin/arm64; creates GitHub Release with changelog body, binaries, and SHA256 checksums
- `scripts/build-release.sh` — cross-compile helper for a single OS/arch pair with stripped binary output
- `scripts/extract-changelog-entry.sh` — extracts a version entry from CHANGELOG.md for use as release notes

### Changed

- `CONTEXT.md` — added CI / Release section documenting the pipeline and action versions
- `.gitignore` — added `/dist/` to ignore build artifacts

## [v0.10.3] - 2026-06-07

- **why:** Fix all 11 actionable findings from the deepseek-v4-flash-max security audit
- **model:** opencode/deepseek-v4-flash
- **tags:** security, audit, crypto, timing-attack, race-condition

### Security

- `internal/server/server.go`: Fixed TOCTOU race in `handleJoin` that allowed two receivers to join the same channel (C-01). Check and add now happen under a single mutex lock.
- `internal/network/network.go`, `signaling.go`: Replaced string comparison with `crypto/subtle.ConstantTimeCompare` for TLS cert fingerprint pinning, closing a timing side channel (H-01).
- `internal/network/network.go`: Implemented proper deadline tracking in `muxedConn` (SetDeadline/SetReadDeadline/SetWriteDeadline) to prevent goroutine leaks on stalled peers (H-02).
- `internal/crypto/crypto.go`: Changed `Identicon` to return `(string, error)` instead of panicking on short input (H-03).
- `internal/crypto/crypto.go`: Replaced `padTo32` silent truncation with `big.Int.FillBytes` for guaranteed fixed-size output (M-01).
- `internal/server/store.go`: Added expiry checks to `StoreBlob` and `FetchBlob` to reject operations on expired channels (M-02).
- `internal/network/signaling.go`: Rewrote `FetchServerFingerprint` to use an HTTPS GET to `/cert` instead of a wasteful double WebSocket connection (M-03).
- `internal/server/server.go`: Changed `/cert` endpoint to serve PEM format (`application/x-pem-file`) instead of raw DER, so users can inspect it directly with `curl -k https://host:4376/cert`.
- `internal/server/ratelimit.go`: Added `slog.Warn` logging when salt rotation fails on `rand.Read` error (M-04).
- `internal/server/server.go`: Added rate limiting to the `/cert` endpoint using the existing `RateLimiter` (M-05).
- `internal/config/config.go`: Changed config directory fallback from `"."` to `/tmp/hermod-<uid>` when `UserHomeDir` fails (M-06).
- `internal/cli/tx.go`: Moved transfer code output from stdout to stderr to prevent log capture of the PAKE passphrase (M-07).

### Changed

- `CONTEXT.md`: Documented H-04 design rationale for storing server private key in config.yaml

### Fixed

- All test helpers that capture the transfer code now redirect both stdout and stderr to the same pipe (M-07 compatibility)

## [0.10.2] - 2026-06-07

- **why:** Migrate historical worklogs from `docs/worklogs/` to proper CHANGELOG.md format
- **model:** opencode/deepseek-v4-flash
- **tags:** docs, chore, changelog, security-audit

### Added

- Security audit report `audit-deepseek-v4-flash-max.md` covering 17 findings across the full codebase

### Changed

- Created `CHANGELOG.md` with all 22 historical version entries (v0.1.0 through v0.10.1) in Keep a Changelog format
- Removed 23 old worklog files from `docs/worklogs/` directory
- Added `docs/worklogs/` to `.gitignore` to prevent future worklog files from being tracked

## [0.10.1] - 2026-05-31

- **why:** Audit reference codes must not appear in user-facing output
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** cli, security-audit, ux

### Fixed

- Remove `(L-05)` security-audit tag from `trust --fingerprint` flag help text in `trust.go`

## [0.10.0] - 2026-05-31

- **why:** Improve transfer UX with consistent progress bars and a quiet mode
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** cli, ux, progress-bar, quiet-mode

### Added

- `-q`/`--quiet` global flag that suppresses all status output while always showing errors
- `streamBar` type with pv-style bounce progress bar that resizes with the terminal (`internal/cli/stream_bar.go`)

### Changed

- Unified all progress bars to `#`/`.` style via `newHashBar`
- `"hermod serve listening on"` capitalisation changed to `"Listening on"`

### Fixed

- Text/stream bar corrupted stdout with ANSI escape codes on stderr

## [0.9.0] - 2026-05-30

- **why:** Four user-reported UX improvements and version constant so plain `go build` shows the real version
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** cli, ux, rx, serve, version

### Added

- `--version`/`-V` flag to root command wired to cobra's built-in version support
- Receive completion message: `"Receive and verification complete."` on successful receive
- `internal/cli/version.go` with embedded `appVersion` constant as default fallback
- `scripts/bump-version.sh` now patches the version constant in `version.go` alongside `VERSION` and `BLUEPRINT.md`

### Changed

- `serve` startup now prints the server certificate fingerprint so operators can share it
- `scripts/bump-version.sh` now patches version in `BLUEPRINT.md` on every bump

### Fixed

- Extra blank line after progress bar for file transfers in `rx.go`
- Plain `go build ./cmd/hermod/` now produces the correct version without requiring `-ldflags`

## [0.8.1] - 2026-05-30

- **why:** Fix all LOW severity findings from the claude-sonnet-4-6 security audit
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** security, fix, crypto, server, network, cli

### Fixed

- SAS context binding — `ExportKeyingMaterial` now binds the channel ID as context (L-01)
- Ephemeral and server certificates switched from RSA-2048 to ECDSA P-256 (L-02)
- `randScalar` replaced biased modular reduction with true rejection sampling (L-03)
- `handleJoin` rejects a second receiver on the same channel (L-04)
- `hermod trust` gained `--fingerprint` for pre-known fingerprint verification (L-05)
- WebSocket upgrader now blocks browser cross-origin connections (L-06)
- `HolePunch` accepts a CPace-derived 4-byte nonce making probe packets session-unique (L-07)
- `SignalingClient.WithContext` goroutine now exits on `Close()` via a `done` channel (L-08)

## [0.8.0] - 2026-05-30

- **why:** Resolve all medium-severity findings from the audit-sonet46.md security audit
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** security, crypto, transfer, server, config

### Fixed

- Server certificate is now non-CA with 1-year validity and startup expiry warnings (M-01)
- Endpoint bundles bind the channel ID as AES-GCM AAD (M-02)
- Rate-limiter bucket map pruned every 10 minutes via background ticker (M-03)
- `handleJoin` rejects receivers for non-existent channels (M-05)
- `/cert` endpoint now correctly serves the DER-encoded server certificate (M-06)
- All transfer kinds compute SHA-256 in parallel during streaming with trailing metadata (M-07)

## [0.7.5] - 2026-05-30

- **why:** Fix H-02 timing side channel — try-and-increment hash-to-curve leaks loop count via timing
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** security, crypto, cpace, rfc9380, sswu, timing-side-channel

### Fixed

- Replaced try-and-increment `cpaceGenerator` with RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` constant-branch hash-to-curve implementation in `internal/crypto/hash_to_curve.go`
- Added `filippo.io/nistec v0.0.4` dependency
- All five RFC 9380 Appendix J.1.1 test vectors pass

## [0.7.4] - 2026-05-30

- **why:** Security audit H-01 — CPace role parameter was silently dropped, leaving role domain separation unimplemented
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** security, crypto, cpace, pake, h01

### Fixed

- Added `role` field to `CPaceSession` and updated `CPaceFinish` to derive ISK as `SHA-256(iskX || pubSender || pubReceiver)`, binding role into the shared secret
- Added `TestCPaceRoleSeparation` regression test

## [0.7.3] - 2026-05-30

- **why:** Fix H-03 — transfer code wordlist had insufficient entropy and two selection defects
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** security, crypto, entropy, wordlist

### Fixed

- Replaced 255-entry custom wordlist with complete EFF Short Wordlist 1 (1296 unique entries)
- Replaced biased `int(b) % len(list)` byte-modulo selection with `randomWordIndex()` using rejection sampling on `uint16` values
- Added `TestWordlistIntegrity` to guard against regressions

## [0.7.2] - 2026-05-30

- **why:** Critical path traversal vulnerability (C-01) allowed writing files outside the receiver's destination directory
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** security, fix, c-01, path-traversal

### Fixed

- Added `filepath.Base` sanitization with `"received"` fallback in `SafeDestinationPath` (`pkg/transfer/transfer.go`)
- Defense-in-depth second layer in `saveToFile` (`internal/cli/rx.go`)
- Added `TestSafeDestinationPathTraversal` covering four traversal patterns

## [0.7.1] - 2026-05-29

- **why:** `tx` and `rx` connected to signaling servers without any certificate verification when no fingerprint was pinned
- **model:** opencode/claude-sonnet-4-6
- **tags:** security, tls, certificate, trust

### Added

- `requireTrustedServer` in `internal/cli/server_trust.go` returns the pinned SHA-256 fingerprint or fails with actionable error
- Check wired into `runTx` and `runRx` before any network call

### Fixed

- All integration and e2e test helpers now pin the server certificate in a temp config

## [0.7.0] - 2026-05-29

- **why:** Close the last open gap — add a declarative testscript full-transfer scenario
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** e2e, testscript, testing

### Added

- `e2e/testdata/scripts/transfer.txtar` — declarative testscript that starts a signaling server, runs `hermod tx`, `hermod rx`, and asserts file integrity
- Three custom testscript commands: `start-server`, `tx-background`, `tx-wait`

### Removed

- `GAP.md` — all gaps are now resolved

## [0.6.0] - 2026-05-29

- **why:** Client IPs stored in plaintext in rate limiter; documentation out of sync with resolved gaps
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** security, privacy, ratelimit, docs

### Added

- Daily-rotating HMAC-SHA256 IP hashing in `internal/server/ratelimit.go` — raw IPs are never stored
- Salt is 32 bytes from `crypto/rand`, replaced every UTC calendar day with buckets cleared on rotation
- Three internal tests covering key hashing, rotation clearing, and day-boundary reset

### Changed

- Synced `BLUEPRINT.md`, `CONTEXT.md`, `docs/api.md`, and `docs/protocol.md` to reflect IP-hashing design

## [0.5.0] - 2026-05-29

- **why:** GAP.md sections 5 and 6 were unimplemented high-severity security gaps
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** security, server, relay, limits, cli

### Added

- `dropChannel` and `recordFailureAndDrop` helpers in `internal/server/server.go`
- Relay loop tracks CPace protocol violations and terminates peer connections after `maxCPaceFailures`
- Relay rejects blobs beyond `maxBlobsPerChannel` with `MsgError`
- `--max-cpace-failures` (default 3) and `--max-blobs-per-channel` (default 10) flags on `hermod serve`
- Tests `TestServerBlobLimitEnforced` and `TestServerCPaceFailureLimitEnforced`

## [0.4.1] - 2026-05-29

- **why:** Resolve all four GAP.md criticals — flaky e2e cancel test, two packages below 80% coverage, and missing enforcement script
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** test, coverage, fix, cli, network, e2e

### Added

- Unit tests, SAS error-path tests, and in-package integration test for `internal/cli`
- `scripts/check-coverage.sh` to abort the build when any required package falls below 80%

### Changed

- Raised `internal/cli` coverage to 81.3% and `internal/network` coverage to 86.6%

### Fixed

- `TestRxCancelCleansUpTempFile` race — increased source file to 16 MiB and replaced fixed sleep with polling loop
- SAS error-path test coverage gaps

## [0.4.0] - 2026-05-29

- **why:** Ctrl+C during a transfer left temp files on disk and gave the peer no notification
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** cancellation, sigint, cleanup, peer-notification

### Added

- `internal/cli/cancel.go` — shared SIGINT context for graceful cancellation
- Temp file cleanup and peer notification on both tx and rx sides
- `cancel_test.go` and `e2e/cancel_test.go` covering unit and end-to-end scenarios

## [0.3.0] - 2026-05-29

- **why:** `--verbose` produced no useful output; users had no visibility into what the app was doing
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** logging, observability, serve, tx, rx, server

### Added

- Structured debug/info/warn/error log calls throughout `serve.go`, `tx.go`, `rx.go`, and `server/server.go`
- `logError` helper in `verbosity.go`
- Logging section in `BLUEPRINT.md` defining level semantics

## [0.2.3] - 2026-05-28

- **why:** Output had an unwanted blank line before the SAS verification header
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** fix, cli, ux

### Fixed

- Removed leading `\n` from `=== Out-of-Band Verification ===` output in `internal/cli/tx.go`

## [0.2.2] - 2026-05-28

- **why:** SAS verification failed when sender piped data via stdin; remaining verify-negotiation code was left uncommitted from prior sessions
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** fix, sas, tty, test, docs

### Added

- `openTTY()` function that reads from `/dev/tty` (Unix) or `CONIN$` (Windows)
- Testable `promptSASVerificationFrom(tlsState, io.Reader)` variant
- `sasStreamConn` refactored from `sasQuicConn` with `quicSASConn` adapter for unit-testable coordination logic
- `internal/cli/sas_test.go` with 9 tests covering regression, both answer orderings, and reject cases
- Symmetric verify-negotiation logic in `rx.go` and `signaling.go`
- Identicon padding fix in `crypto.go`

### Fixed

- SAS prompt no longer reads piped stdin content — reads from `/dev/tty` instead

### Changed

- Updated `README.md` and `docs/protocol.md` to document SAS `/dev/tty` behaviour

## [0.2.1] - 2026-05-28

- **why:** Documentation was stale after v0.2.0 code changes
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** docs, memory, agents, readme, blueprint

### Changed

- Updated `BLUEPRINT.md` version from 0.1.0 to 0.2.0 and added `verbosity.go` to file map
- Updated `README.md` with `--verbose` flag in tx/rx/serve tables and documented `HERMOD_SERVER` and `HERMOD_DEST_DIR` env vars

### Added

- "Docs with Code" rule to `AGENTS.md` requiring docs updated in same commit as code
- `docs/memory/` store with index entry reinforcing docs-with-code rule

## [0.2.0] - 2026-05-28

- **why:** Fix IPv6 endpoint formatting, add `--verbose` flag, and ensure all output is correctly routed to stderr
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** fix, feat, cli, verbose, ipv6, stderr

### Added

- `--verbose` persistent flag with five levels (`none`, `error`, `warning`, `info`, `debug`)
- `internal/cli/verbosity.go` — centralised verbosity handling

### Fixed

- IPv6 loopback address formatting by replacing `fmt.Sprintf("%s:%d", ip, port)` with `net.JoinHostPort`

### Changed

- All diagnostic output (status messages, progress bars, logs) routed to stderr via `slog`
- Stdout now carries only payload data and the transfer code

## [0.1.0] - 2026-05-28

- **why:** Initial release of Hermod — secure P2P file and text transfer tool
- **model:** github-copilot/claude-sonnet-4.6
- **tags:** feat, initial-release, p2p, quic, cpace, cli, e2e

### Added

- WebSocket signaling server with in-memory store and rate limiting
- UDP hole-punching and QUIC transport with ephemeral TLS certificates
- CPace PAKE key exchange over P-256
- AES-GCM encrypted file and text transfer
- SAS verification with identicon display
- Cobra CLI with `serve`, `trust`, `tx`, and `rx` commands
- Tx/Rx ack stream to prevent QUIC connection teardown races
- Full test suite across config, crypto, server, network, transfer, and E2E protocol + CLI tests
