# Hermod — Gap Analysis

Generated: 2026-05-29. Compares TASK.md requirements against current implementation.

---

## 🔴 Critical — Tests broken or coverage failing

### 1. `TestRxCancelCleansUpTempFile` fails in the full e2e suite

**File:** `e2e/cancel_test.go`

The 1 MiB test file transfers in under 300 ms over loopback. The transfer completes before `time.Sleep(300ms)` elapses and SIGINT is fired. Once both `runTx` and `runRx` return, all `signal.NotifyContext` handlers have exited. The SIGINT then hits the test binary's default handler and the process dies with `signal: interrupt`.

The test passes in isolation (`go test -run TestRxCancelCleansUpTempFile ./e2e/...`) but fails as part of the full suite (`go test ./e2e/...`).

**Fix:** Use a larger source file (e.g. 16 MiB) or add explicit synchronization to confirm rx is mid-receive before sending SIGINT.

---

### 2. `internal/cli` coverage: 24.6% — required 80%

**Reference:** TASK.md §27

The following functions have 0% coverage: `runTx`, `runRx`, `runServe`, `runTrust`, `buildPayload`, `receivePayload`, `saveToFile`, `appendLenPrefix`, `readLenPrefixed`. The cli package has no unit tests for these paths. All coverage comes from e2e tests in a separate package, which do not count toward `internal/cli` statement coverage.

**Fix:** Add unit tests for cli functions using interface mocks for the signaling and network layers, or restructure the e2e harness so test execution counts toward the cli package.

---

### 3. `internal/network` coverage: 63.4% — required 80%

**Reference:** TASK.md §27

Functions with 0% coverage: `HolePunch`, `DialQUIC`, `ListenQUIC`, `makeCertPinner`, `muxedConn.ReadFrom`. These are exercised only through e2e tests, which do not count toward `internal/network` statement coverage.

**Fix:** Add unit tests within the package — `HolePunch` can be tested with a `net.Pipe`-backed `PacketConn`; cert pinning and `muxedConn` can be tested with in-process connections.

---

### 4. No 80% coverage enforcement script

**Reference:** TASK.md §27 — *"The build process must abort with an error code if the total coverage falls below this threshold."*

No Makefile, shell script, or CI step runs `go test -coverprofile=coverage.out ./...` and fails the build when total coverage is below 80%.

**Fix:** Add a script (e.g. `scripts/check-coverage.sh`) that runs the coverage command and exits non-zero if any package is below 80%.

---

## 🟠 High — Security and behavioural spec gaps

### 5. Max 3 CPace failures per channel — never enforced

**Reference:** TASK.md §5 — *"The server strictly enforces a maximum of 3 failed CPace handshake attempts per channel ID. Upon the third failed cryptographic validation, the server immediately drops the WebSocket connections, invalidates the channel ID, and purges the associated state from the database."*

`SignalingStore.RecordFailure()` is defined and implemented in `MemoryStore` but is **never called** anywhere in `server.go`. The relay loop (`relay()`) processes blobs unconditionally with no failure tracking. An attacker can send unlimited malformed CPace messages.

**Fix:** Call `store.RecordFailure(channelID)` when a blob cannot be decrypted or when the CPace exchange fails. After 3 failures, drop both WebSocket connections and call `store.DeleteChannel(channelID)`.

---

### 6. Hard message limit per channel — never enforced

**Reference:** TASK.md §9 — *"Hard limits exist on signaling messages per channel to prevent relay saturation."*

`blobCount` is incremented in the `relay()` loop but there is no maximum defined. A client can send unlimited blobs and the server will relay all of them indefinitely.

**Fix:** Define a `maxBlobsPerChannel` constant (e.g. 10) and return an error and close the connection when the count is exceeded.

---

## 🟡 Medium — Privacy spec gaps

### 7. IP hashing with daily rotating salt — not implemented

**Reference:** TASK.md §9 — *"Client IPs are hashed with a daily rotating salt in memory to prevent tracking."*

`RateLimiter` in `internal/server/ratelimit.go` keys the bucket map on the raw IP string (e.g. `"1.2.3.4"`). There is no salt and no daily rotation. IP addresses are stored in plaintext, linking requests to real client IPs across the full uptime of the server process.

**Fix:** Introduce a daily-rotating in-memory salt. Hash the IP prefix with `HMAC-SHA256(salt, prefix)` before using it as a map key.

---

## 🟢 Low — Completeness gaps

### 8. testscript E2E scenarios are minimal

**Reference:** TASK.md §27 — describes a complete testscript flow: compile binary → start `hermod serve` → run `hermod tx` → parse stdout for transfer code → run `hermod rx` concurrently → compare SHA-256 of sent and received payloads.

Current `e2e/testdata/scripts/` contains only two smoke tests (`help.txtar`, `commands_help.txtar`) that check help text output. The full transfer flow is covered only by Go API integration tests (`integration_test.go`, `cli_transfer_test.go`), not by declarative `.txtar` testscript scenarios.

**Fix:** Add a `transfer.txtar` testscript that starts `hermod serve` in the background, runs `hermod tx`, captures the transfer code from stdout, runs `hermod rx`, and asserts file integrity.

---

## Covered — Not gaps

The following TASK.md items that might appear absent are intentional architecture decisions recorded in BLUEPRINT.md:

| TASK.md item | Resolution |
|---|---|
| SQLite `--db` flag for `serve` | Replaced by `MemoryStore`; SQLite dependency removed (BLUEPRINT.md §Implementation) |
| Log output to `~/.local/state/hermod/app.log` | Changed to stderr-only logging; no rolling log file (BLUEPRINT.md §Logging) |
| `github.com/cloudflare/circl` for CPace | Replaced by custom P-256 implementation; circl not in `go.mod` (BLUEPRINT.md §crypto) |

---

## Summary

| # | Severity | Area | Status |
|---|---|---|---|
| 1 | 🔴 Critical | `TestRxCancelCleansUpTempFile` race condition | Failing |
| 2 | 🔴 Critical | `internal/cli` coverage 24.6% | Below threshold |
| 3 | 🔴 Critical | `internal/network` coverage 63.4% | Below threshold |
| 4 | 🔴 Critical | No coverage enforcement script | Missing |
| 5 | 🟠 High | CPace failure limit not enforced | Unimplemented |
| 6 | 🟠 High | Per-channel message limit not enforced | Unimplemented |
| 7 | 🟡 Medium | IP hashing with rotating salt | Unimplemented |
| 8 | 🟢 Low | testscript full-transfer scenario | Minimal |
