---
when: 2026-05-03T00:59:52Z
why: ConnectionError for expected conditions like channel_not_found fell into the generic Exception handler which logged a full traceback
what: split CLI exception handlers so protocol errors exit cleanly without a traceback
model: github-copilot/claude-sonnet-4.6
tags: [fix, cli, ux, error-handling]
---

Added a `(ConnectionError, ValueError, OSError)` catch clause above the generic
`Exception` handler in both `transmit` and `receive` commands in
`src/hermod/cli/main.py`. Known user-facing conditions (wrong channel, connection
refused, invalid transfer code) now print a clean error line and exit 1 — no
traceback. Truly unexpected errors still reach `logger.exception` so they are
logged with a stack trace. Bumped to v0.3.6.
