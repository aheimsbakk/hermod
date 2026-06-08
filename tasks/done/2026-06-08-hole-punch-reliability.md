# Persistent hole punch probing + QUIC keepalive

## Problem

`HolePunch` returns success as soon as a probe or ack is received, then kills the probe goroutine via `defer cancel()`. This creates a race:

- One side receives the peer's probe first → returns success, stops probing
- The other side has not yet received any probe or ack → starves → times out

The race is directional (depends on which side is TX/RX) because each side probes a different candidate list (the other side's endpoints), and asymmetric NAT behavior treats those paths differently.

A secondary issue: between `HolePunch` returning and the QUIC transport starting (DialQUIC/ListenQUIC), there is a window where no probes are sent. NAT mappings with short timeouts can expire in this gap, causing the QUIC handshake to fail.

## Solution: Persistent probe lifecycle tied to QUIC connection

### What to change

1. **Move probe goroutine ownership out of `HolePunch`** — instead of creating the probe goroutine inside `HolePunch` and cancelling it on return, the caller (tx.go / rx.go) creates it before calling `HolePunch` and cancels it after the QUIC connection is established (or the transfer is done).

2. **Pass a probe cancellation context into `HolePunch`** — the function receives a `probeCtx context.Context` from the caller, separate from the hole-punch `ctx`. The probe goroutine uses `probeCtx`. `HolePunch` never cancels it.

3. **Lifecycle in tx.go / rx.go**:
   - Create `probeCtx, probeCancel := context.WithCancel(ctx)` before calling `HolePunchDual`
   - Pass `probeCtx` down to the probe goroutine (via `HolePunch`)
   - After `HolePunch` succeeds AND the QUIC connection is established (DialQUIC returns on TX, Accept returns on RX), call `probeCancel()`
   - On early error or cancellation, `defer probeCancel()` ensures cleanup

### What DOES NOT change

- The `HolePunch` return condition remains: return on first probe or ack received (fast path preserved)
- Probe format (3 bytes, same nonce structure)
- Probe frequency (200ms ticker)
- No changes to the signaling protocol, endpoint bundles, or QUIC setup
- No new message types

### Why this works

- Both sides keep probing until both have succeeded — no starvation
- The timing race is eliminated: whichever side succeeds first keeps the path alive for the other
- The QUIC setup gap is bridged: probes maintain NAT mappings between HolePunch return and QUIC handshake
- TX/RX role becomes irrelevant for hole punch reliability

### Files to change

- `internal/network/network.go` — `HolePunch` signature: accept a probe context (or pass probes from outside). The probe goroutine should use this context instead of the hole-punch timeout context.
- `internal/cli/tx.go` — create probe context before `HolePunchDual`, cancel after `DialQUIC` succeeds
- `internal/cli/rx.go` — create probe context before `HolePunchDual`, cancel after `ListenQUIC` + `Accept` succeeds
- `internal/network/network_internal_test.go` — update tests to pass the new probe context parameter where needed

### Implementation notes

- The probe context should be derived from the main operation context (ctx with SIGINT/SIGTERM), so probes stop on user cancellation
- Keep `defer probeCancel()` in tx.go and rx.go for the error/early-return paths
- `HolePunchDual` must also accept and forward the probe context to each `HolePunch` call
