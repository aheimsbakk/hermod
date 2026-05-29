---
when: 2026-05-29T17:22:53Z
why: Ctrl+C during a transfer left temp files on disk and gave the peer no notification
what: Add graceful cancellation with SIGINT handling, temp cleanup, and peer notification
model: github-copilot/claude-sonnet-4.6
tags: [cancellation, sigint, cleanup, peer-notification]
---

Implemented graceful Ctrl+C cancellation for both tx and rx sides: `internal/cli/cancel.go` provides a shared SIGINT context, `cancel_test.go` and `e2e/cancel_test.go` cover unit and end-to-end scenarios. Modified `tx.go`, `rx.go`, `serve.go`, and `config.go` to propagate the cancel context and clean up temp files. Updated `BLUEPRINT.md`, `CONTEXT.md`, `docs/api.md`, and `docs/protocol.md` to reflect the new cancellation flow. Bumped to v0.4.0.
