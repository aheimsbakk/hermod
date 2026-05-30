---
when: 2026-05-30T10:02:39Z
why: Critical path traversal vulnerability (C-01) allowed a malicious sender to write files outside the receiver's destination directory
what: Sanitize received filename with filepath.Base in SafeDestinationPath and saveToFile
model: github-copilot/claude-sonnet-4.6
tags: [security, fix, c-01, path-traversal]
---

Added `filepath.Base` sanitization with a `"received"` fallback in `pkg/transfer/transfer.go:SafeDestinationPath` (primary guard) and `internal/cli/rx.go:saveToFile` (defense-in-depth second layer). Added `TestSafeDestinationPathTraversal` in `pkg/transfer/transfer_test.go` covering four traversal patterns. Updated `docs/protocol.md` to document the receiver-side sanitization. Bumped to v0.7.2.
