---
when: 2026-05-29T18:59:36Z
why: GAP.md §5 and §6 were unimplemented high-severity security gaps
what: Enforce per-channel CPace failure limit and blob count limit in the signaling relay
model: github-copilot/claude-sonnet-4.6
tags: [security, server, relay, limits, cli]
---

Added `dropChannel` and `recordFailureAndDrop` helpers in `internal/server/server.go`. The relay loop now tracks CPace protocol violations via `store.RecordFailure` and terminates all peer connections once `maxCPaceFailures` is reached; it also rejects blobs beyond `maxBlobsPerChannel` with a `MsgError`. Both limits are configurable via `hermod serve --max-cpace-failures` (default 3) and `--max-blobs-per-channel` (default 10). `NewServer` signature extended with the two new int params; all six call sites updated. New tests `TestServerBlobLimitEnforced` and `TestServerCPaceFailureLimitEnforced` added to `internal/server/server_ws_test.go`. Bumped to v0.5.0.
