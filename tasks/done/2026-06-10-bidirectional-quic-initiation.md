Race QUIC dial and accept on both sides after hole punch so the connection succeeds even when only one direction traverses the NAT. Currently the sender always dials and the receiver always listens; if that specific direction fails, the transfer fails.

## Changes

### `internal/network/network.go`

- **Add** `RaceQUIC(ctx, mux, peerAddr, baseTLS, cert, peerCertHash) (*quic.Conn, error)`:
  Creates a single `quic.Transport` on the muxed connection, starts a listener, then races a dial to `peerAddr` and an accept on the listener. Returns whichever connection succeeds first. Cancels the losing goroutine via context.
- TLS config is set up internally (same as `DialQUIC` / `ListenQUIC`):
  - `Certificates` from the `cert` parameter
  - `ClientAuth = tls.RequireAnyClientCert`
  - `InsecureSkipVerify = true`
  - `VerifyPeerCertificate` pins `peerCertHash`
  - `NextProtos = []string{"hermod-p2p"}`
- QUIC config: `MaxIdleTimeout: 30s`, `KeepAlivePeriod: 5s`
- Keep `DialQUIC` and `ListenQUIC` for now (other callers may exist)

### `internal/cli/tx.go`

- In `runTx`, replace the `DialQUIC` call with `RaceQUIC`:
  - Same TLS cert setup (already has `Certificates`)
  - Same peer address and fingerprint
  - No `ClientAuth` needed on the caller side — `RaceQUIC` sets it

### `internal/cli/rx.go`

- In `runRx`, replace `ListenQUIC` + `ln.Accept(ctx)` with `RaceQUIC`:
  - Same TLS cert, base config, and fingerprint
  - Address comes from `punchResult.PeerAddr`
  - Update log message from "accepted from sender" to "established" (generic, bidirectional)

### `docs/protocol.md`

- Update the **QUIC connection** section (line 147–156):
  - Replace "the receiver acts as the QUIC server and the sender as the client" with "both peers race a QUIC dial and accept; the first handshake wins"
  - Document the dual-role TLS config (`ClientAuth`, mutual cert pinning)

### `docs/api.md`

- Document `RaceQUIC` signature and behavior
- Update or remove `DialQUIC` / `ListenQUIC` entries if they become unused

## Cleanup checklist

- [x] `go test ./internal/network/...` passes
- [x] `go test ./internal/cli/...` passes
- [x] `go test ./e2e/...` passes
- [x] No references to `DialQUIC` or `ListenQUIC` remain in `cli/`
- [x] `docs/protocol.md` reflects bidirectional initiation correctly
- [x] All affected log messages are still accurate
