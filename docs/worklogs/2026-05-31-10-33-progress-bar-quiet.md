---
when: 2026-05-31T10:33:18Z
why: improve transfer UX with consistent progress bars and a quiet mode
what: add -q/--quiet flag, pv-style stream progress bar, consistent #/. bar style, fix text/stream bar corruption
model: github-copilot/claude-sonnet-4.6
tags: [cli, ux, progress-bar, quiet-mode]
---

Added `-q`/`--quiet` global flag that suppresses all status output (progress bars, status lines, cancellation messages) while always showing errors and transferred content; `-v` remains orthogonal. Replaced the fixed-width spinner-based stream progress bar with a custom `streamBar` type (`stream_bar.go`) that queries terminal width on every tick via `golang.org/x/term`, giving a pv-style `sending |...###...|` bounce that resizes with the terminal. Unified all progress bars to `#`/`.` style via `newHashBar`; removed the broken text/stream bar that corrupted stdout with ANSI codes on stderr. Fixed `"hermod serve listening on"` capitalisation to `"Listening on"`. Bumped to v0.10.0. Files: `internal/cli/root.go`, `verbosity.go`, `tx.go`, `rx.go`, `serve.go`, `stream_bar.go` (new), `unit_test.go`.
