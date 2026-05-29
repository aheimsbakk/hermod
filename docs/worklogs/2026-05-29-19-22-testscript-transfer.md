---
when: 2026-05-29T19:22:39Z
why: close the last open gap — add a declarative testscript full-transfer scenario
what: add transfer.txtar testscript with custom commands; remove GAP.md; bump to v0.7.0
model: github-copilot/claude-sonnet-4.6
tags: [e2e, testscript, testing]
---

Added `e2e/testdata/scripts/transfer.txtar`: a declarative `.txtar` testscript
that starts an in-process signaling server, runs `hermod tx` in a background
goroutine to capture the transfer code, executes `hermod rx` as a subprocess,
and asserts byte-for-byte file integrity with `cmp`. Three custom testscript
commands (`start-server`, `tx-background`, `tx-wait`) were implemented in
`e2e/testscript_cmds_test.go` and registered in `e2e/e2e_test.go`. GAP.md was
removed as all gaps are now resolved.
