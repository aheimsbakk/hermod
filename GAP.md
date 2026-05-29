# Hermod — Gap Analysis

Generated: 2026-05-29. Compares TASK.md requirements against current implementation.

---

## ✅ Resolved — Previously critical

### 1. `TestRxCancelCleansUpTempFile` fails in the full e2e suite

**File:** `e2e/cancel_test.go`  
**Status: RESOLVED**

Increased source file from 1 MiB to 16 MiB and replaced the fixed `time.Sleep(300ms)` with a polling loop (up to 8 s) that waits for a `.hermod_tmp` file to appear before sending SIGINT. The test now passes reliably in the full suite.

---

### 2. `internal/cli` coverage: 24.6% → **81.3%** — required 80%

**Reference:** TASK.md §27  
**Status: RESOLVED**

Added `internal/cli/unit_test.go` (helper-function unit tests), `internal/cli/sas_test.go` additions (all `performSASCoordinatedWith` error paths, both-reject case), and `internal/cli/transfer_integration_test.go` (in-package integration tests for text, file, stdin, and SAS-verified transfers). `openTTYFunc` and `stdoutIsTTY` injection points were added to make TTY-dependent paths testable without a real terminal.

---

### 3. `internal/network` coverage: 63.4% → **86.6%** — required 80%

**Reference:** TASK.md §27  
**Status: RESOLVED**

Rewrote `internal/network/network_internal_test.go` with a `stubPacketConn` helper and tests covering: `readLoop` error and routing branches, `muxedConn.ReadFrom` (closed and normal paths), `makeCertPinner` (no-certs, hash-mismatch, and match paths), all `HolePunch` branches (timeout, probe received, ack received, short-probe ignored, ticker sends), and a full loopback `DialQUIC`/`ListenQUIC` handshake test.

---

### 4. No 80% coverage enforcement script → **`scripts/check-coverage.sh`**

**Reference:** TASK.md §27  
**Status: RESOLVED**

Added `scripts/check-coverage.sh`. Runs each required package (`./internal/cli/...`, `./internal/network/...`) with its own coverprofile, parses the total percentage, and exits non-zero if any package falls below 80%.

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
| 1 | 🔴 Critical | `TestRxCancelCleansUpTempFile` race condition | ✅ Resolved |
| 2 | 🔴 Critical | `internal/cli` coverage 24.6% | ✅ Resolved — 81.3% |
| 3 | 🔴 Critical | `internal/network` coverage 63.4% | ✅ Resolved — 86.6% |
| 4 | 🔴 Critical | No coverage enforcement script | ✅ Resolved |
| 5 | 🟠 High | CPace failure limit not enforced | Unimplemented |
| 6 | 🟠 High | Per-channel message limit not enforced | Unimplemented |
| 7 | 🟡 Medium | IP hashing with rotating salt | Unimplemented |
| 8 | 🟢 Low | testscript full-transfer scenario | Minimal |
