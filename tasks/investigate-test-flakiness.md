# Investigate flaky integration tests

## Problem

Several end-to-end and CLI integration tests fail intermittently with `"join channel: server error: operation failed"` when run as part of the full test suite (`go test ./...`). They pass reliably when run in isolation.

Observed failures:
- `e2e.TestCLITransferFile` — "rx error: join channel: server error: operation failed"
- `cli.TestTransfer_File_Internal` — "rx error: join channel: server error: operation failed"
- `e2e.TestCLITransferText` — occasionally hangs for >2 minutes (WebSocket ReadJSON stuck in server relay loop)

The `"operation failed"` response is a generic error returned by the signaling server for three conditions (see `internal/server/server.go`):
1. Rate-limited join
2. Non-existent channel (receiver joins before sender allocates)
3. Duplicate receiver

The hangs suggest a deeper issue — possibly a goroutine leak or a deadlock in the relay loop when a peer disconnects during transfer setup.

## What to investigate

1. **Reproduce consistently**: Identify the minimal conditions that trigger the race. Try running the full suite with `-count=5 -race` to surface data races.
2. **Server-side relay loop** (`internal/server/server.go` — `relay()`): review whether a WebSocket read error from one peer properly unblocks the other peer's read. Look for missing `select` patterns or goroutines that can outlive the channel lifecycle.
3. **Test isolation**: check whether tests share state via global variables (e.g. `ipv4Only`, `ipv6Only` in `internal/cli/`).
4. **Port reuse**: verify that `startCLIServer` / `startLocalServer` do not race on port allocation when multiple tests start servers concurrently.
5. **Propose fixes** for the identified root cause(s).

## Files of interest

- `e2e/cli_transfer_test.go` — `cliTransfer()`, `startCLIServer()`
- `internal/cli/transfer_integration_test.go` — `cliTransferInternal()`, `startLocalServer()`
- `internal/server/server.go` — `relay()`, `handleJoin()`, `handleAllocate()`
- `internal/cli/root.go` — global flags (`ipv4Only`, `ipv6Only`)
