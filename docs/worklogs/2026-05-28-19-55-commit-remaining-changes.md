---
when: 2026-05-28T19:55:04Z
why: Previous wrap-up left verify-negotiation code, tests, and docs uncommitted; docs also needed updating for the /dev/tty SAS fix
what: Commit all remaining verify-negotiation and SAS changes; update README and protocol docs
model: github-copilot/claude-sonnet-4.6
tags: [docs, fix, feat, test, chore]
---

Committed all files left unstaged from two prior sessions: symmetric verify-negotiation logic in `rx.go` and `signaling.go`, identicon padding fix in `crypto.go`, signaling context propagation, new network and signaling tests, and the `e2e/verify_negotiation_test.go` suite. Updated `README.md` to document that `--verify` reads from `/dev/tty` so piped stdin does not interfere. Updated `docs/protocol.md` with the same note in the SAS verification section. All docs now match the implemented behaviour at v0.2.2.
