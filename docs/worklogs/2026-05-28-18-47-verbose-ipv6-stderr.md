---
when: 2026-05-28T18:47:28Z
why: Fix IPv6 endpoint formatting, add --verbose flag, and ensure all output is correctly routed to stderr
what: v0.2.0 — IPv6 fix, --verbose log levels, clean stdout
model: github-copilot/claude-sonnet-4.6
tags: [fix, feat, cli, verbose, ipv6, stderr]
---

Fixed IPv6 loopback address formatting in tx/rx by replacing `fmt.Sprintf("%s:%d", ip, port)` with `net.JoinHostPort`, resolving the "too many colons in address" error on localhost transfers. Added `--verbose` persistent flag to the root command with five levels (`none`, `error`, `warning`, `info`, `debug`; default `none`) — silences the quic-go UDP buffer advisory by default and routes all diagnostic output through `slog`. Audited and corrected all print statements across tx, rx, trust, and serve so stdout carries only payload data and the transfer code; all status messages, progress bars, and logs go to stderr. Bumped to v0.2.0. Files touched: `internal/cli/verbosity.go` (new), `root.go`, `tx.go`, `rx.go`, `trust.go`, `serve.go`.
