---
when: 2026-05-29T20:16:13Z
why: tx and rx connected to signaling servers without any certificate verification when no fingerprint was pinned
what: enforce trusted-server check in tx and rx; abort with clear error if server is not in trusted_servers
model: opencode/claude-sonnet-4-6
tags: [security, tls, certificate, trust]
---

Added `requireTrustedServer` in `internal/cli/server_trust.go` which returns the pinned SHA-256 fingerprint or fails with an actionable error directing the user to run `hermod trust`. Wired the check into `runTx` (`tx.go`) and `runRx` (`rx.go`) before any network call. Updated all integration and e2e test helpers (`transfer_integration_test.go`, `cli_transfer_test.go`, `cancel_test.go`, `testscript_cmds_test.go`) to pin the server certificate in a temp config so existing tests continue to pass. Bumped to v0.7.1.
