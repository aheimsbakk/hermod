# Investigate flaky integration tests — COMPLETED

## Problem

Several end-to-end and CLI integration tests fail intermittently with
WebSocket close 1006 errors when run as part of the full test suite
(`go test ./...`). They pass reliably when run in isolation.

All failures trace back to the sender's `RecvBlob()` failing with
`"receive CPace message from peer: websocket: close 1006"`.

## Root causes found and fixed

### 1. Port reuse TOCTOU race in test helpers
Tests called `net.Listen("tcp", ":0")` (get a random port), closed the
listener, then passed the port string to `ListenAndServe`. Between the
close and the serve, another test could bind the same port.

**Fix:** Added `Serve(ctx, ln net.Listener, tlsCfg)` to
`internal/server/server.go` that accepts an existing listener.
All test helpers pass a kept-open listener.

### 2. Relay not unblocking the other peer on disconnect
When one peer disconnected, the relay's defer closed the channel and
removed the waiter entries, but the other peer's `ReadJSON` in the relay
remained stuck forever.

**Fix:** The relay's defer now explicitly closes the peer's WebSocket
connection, which unblocks the peer's `ReadJSON`.

### 3. Concurrent write panic in handleAllocate / handleJoin
Both `handleAllocate` and `handleJoin` wrote `WriteJSON` after releasing
`s.mu`. Gorilla WebSocket panics on concurrent writes to the same
connection (`concurrent write to websocket connection`).

**Fix:** All `WriteJSON` calls moved inside `s.mu` in both functions.

### 4. handleJoin sends MsgOK after adding receiver to waiters (the final root cause)
In `handleJoin`, the receiver was added to `s.waiters[channelID]` before
`MsgOK` was written to the receiver's connection. The sender's relay
goroutine (started by `handleAllocate`) runs concurrently. After finding
the receiver in `waiters`, it could forward a `MsgBlob` (the sender's
CPace message) to the receiver's connection before `handleJoin` wrote
`MsgOK`. The receiver's `Join()` would then read the blob, try to parse
it as an IP response map, fail, and disconnect. The relay would then
close the sender's connection via `peer.conn.Close()`, causing a 1006
error on the sender's `RecvBlob()` — the exact error seen in the flake.

**Fix:** `handleJoin` now writes `MsgOK` to the receiver **before**
adding it to `waiters`. This ensures the relay cannot find the receiver
until MsgOK is already in the TCP buffer. Verified 30/30 passes of the
full e2e suite.

### 5. Global state leakage between CLI tests
`ipv4Only`, `ipv6Only`, and `quietMode` in `internal/cli/root.go` are
package-level globals set by cobra's `PersistentPreRunE`. Tests that ran
`cli.ExecuteArgs`/`cli.Execute` (including testscript scripts that call
`hermod`) leaked modified globals to subsequent tests.

**Fix:** Added `t.Cleanup` reset in test helpers.

### 6. Transfer code printed before channel allocation
`tx.go` printed the transfer code for the user before `Allocate()`
completed. The CLI test started `rx` immediately upon seeing the code,
but the channel might not exist yet on the server.

**Fix:** Move "Transfer code:" print after `Allocate()`.

### 7. Allocate() failed when MsgReady arrived before MsgOK
Due to the concurrent writer goroutines, the sender could receive
`MsgReady` before `MsgOK`. `Allocate()` previously failed to parse
`MsgReady` as the allocation response.

**Fix:** `Allocate()` loops on non-error message types, accepting both
`MsgOK` and `MsgReady` as valid first responses.

### 8. Debug logging dropped in
File-based debug logging (`/tmp/hermod_*.log`) was added during
diagnosis and then removed.

**Fix:** Removed `logf`, `logBlob`, `os.OpenFile` calls from
`server.go` and `signaling.go`.

## Coverage

All packages now meet the 80% threshold:
- `internal/cli` — 80.0%
- `internal/config` — 88.2%
- `internal/crypto` — 89.6%
- `internal/network` — 82.7%
- `internal/server` — 84.4%

New test files added:
- `internal/cli/stream_bar_test.go` (10 tests)
- `internal/cli/tx_unit_test.go` (5 tests)
- `internal/cli/tty_unix_test.go` (1 test)
- `internal/config/cert_expiry_test.go` (9 tests)

## Stability

Full e2e suite (`go test -p 1 -count=1 ./e2e/...`):
- 30/30 passes (up from ~1/15 failure rate with GOMAXPROCS>1)
- No longer requires `GOMAXPROCS=1` to pass
