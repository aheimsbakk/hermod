---
when: 2026-05-29T18:43:27Z
why: Resolve all four GAP.md criticals — flaky e2e cancel test, two packages below 80% coverage, and missing enforcement script
what: Fix TestRxCancelCleansUpTempFile race, raise internal/cli to 81.3% and internal/network to 86.6%, add scripts/check-coverage.sh
model: github-copilot/claude-sonnet-4.6
tags: [test, coverage, fix, cli, network, e2e]
---

Increased the cancel-test source file to 16 MiB and replaced the fixed sleep with a polling loop so SIGINT is sent only after the temp file appears (`e2e/cancel_test.go`). Added unit tests, SAS error-path tests, and an in-package integration test for `internal/cli` (new files `unit_test.go`, `sas_test.go`, `transfer_integration_test.go`) backed by `openTTYFunc` and `stdoutIsTTY` injection points in `tx.go` and `rx.go`. Rewrote `internal/network/network_internal_test.go` with `stubPacketConn` and loopback QUIC tests, lifting network coverage to 86.6%. Added `scripts/check-coverage.sh` to abort the build when any required package falls below 80%. Bumped to v0.4.1.
