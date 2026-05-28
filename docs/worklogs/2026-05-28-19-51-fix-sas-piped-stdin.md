---
when: 2026-05-28T19:51:41Z
why: SAS verification always failed when sender piped data via stdin — fmt.Scanln read piped content instead of user input
what: Fix SAS prompt to read from /dev/tty; add unit tests for piped-stdin regression
model: github-copilot/claude-sonnet-4.6
tags: [fix, sas, tty, test]
---

Root cause: `promptSASVerification` used `fmt.Scanln(&answer)` which reads from `os.Stdin`. When the sender ran `echo test | hermod tx -v -`, stdin contained `"test\n"`, so the answer was never `"y"`, causing the sender to send `0x00` and abort both sides. Fixed by introducing `openTTY()` (opens `/dev/tty` on Unix, `CONIN$` on Windows) and a testable `promptSASVerificationFrom(tlsState, io.Reader)` variant. Refactored `sasQuicConn` into `sasStreamConn` (uses `io.ReadWriteCloser`) with a `quicSASConn` adapter so the coordination logic can be unit-tested without a real QUIC connection. Added `internal/cli/sas_test.go` with 9 tests covering the regression, both answer orderings, and reject cases. Bumped to v0.2.2.

Files touched: `internal/cli/tx.go`, `internal/cli/tty_unix.go`, `internal/cli/tty_windows.go`, `internal/cli/sas_test.go`.
