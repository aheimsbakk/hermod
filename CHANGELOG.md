# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
