---
when: 2026-05-29T16:18:23Z
why: --verbose produced no useful output; users had no visibility into what the app was doing
what: add structured debug/info/warn/error log calls throughout serve, tx, rx, and server relay
model: github-copilot/claude-sonnet-4.6
tags: [logging, observability, serve, tx, rx, server]
---

Added `logError` helper to `verbosity.go` and instrumented every significant
step across `serve.go`, `tx.go`, `rx.go`, and `server/server.go` with
`slog`-backed calls at the correct level: debug for internal mechanics, info
for state changes (channel allocated, PAKE complete, QUIC connected, transfer
done), warn for non-fatal problems, and error for unrecoverable failures.
Updated `BLUEPRINT.md` with a Logging section defining level semantics and the
rule that sensitive material must never appear in logs. Bumped to v0.3.0.
