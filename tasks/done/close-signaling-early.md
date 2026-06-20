# Close signaling connection early after blob exchange

The signaling WebSocket connection is currently closed only when `runTx`/`runRx`
returns (`defer sigRaw.Close()` at the top of each function). After blob 4
(the last signaling message), the connection sits idle for the entire duration
of the UDP hole punch, QUIC handshake, and payload transfer — potentially
minutes. This wastes server resources (TCP socket, goroutine, channel state).

## Scope

Two files need a single-line change each. No protocol changes, no new tests
(the existing `defer` already guarantees cleanup on error paths).

## Changes

### `internal/cli/tx.go`

After line 342 (`encPeerBundle, err := sig.RecvBlob()` — receives blob 4), add:

```go
// Signaling work is done — close the WebSocket to free server resources.
sigRaw.Close()
```

The `defer sigRaw.Close()` at line 152 is idempotent (uses `sync.Once` for the
`done` channel and `conn.Close()` is safe to call twice) so it stays as a
safety net for early-error paths that never reach blob 4.

### `internal/cli/rx.go`

After line 310 (`sig.SendBlob(channelID, encMyBundle)` — sends blob 4), add:

```go
// Signaling work is done — close the WebSocket to free server resources.
sigRaw.Close()
```

Same rationale: the defer at line 112 remains for early-error safety.

## Timing safety

- Sender cannot receive blob 4 until the server has received it from the
  receiver and forwarded it. Therefore when the sender closes, the receiver
  has already sent blob 4 and no longer needs the signaling connection.
- The server-side relay cleanup (`server.go` line 447–451) closes the peer's
  WebSocket when one side disconnects. This is harmless since both sides are
  done with signaling by that point.
- `Close()` is safe to call multiple times (`closeOnce.Do` guards `close(c.done)`;
  `c.conn.Close()` returns an error on second call which we ignore).

## Safety net (already in place)

The existing `defer sigRaw.Close()` in both `runTx` and `runRx` ensures cleanup
if the function exits before reaching the new explicit `Close()` calls (e.g.
error during `Allocate`, `WaitReady`, or any blob exchange).

## Cleanup checklist

- [ ] `tx.go`: `sigRaw.Close()` called after `sig.RecvBlob()` (blob 4)
- [ ] `rx.go`: `sigRaw.Close()` called after `sig.SendBlob(...)` (blob 4)
- [ ] `defer sigRaw.Close()` still present in both files (safety net)
- [ ] `go test ./...` passes
- [ ] `go vet ./...` passes
