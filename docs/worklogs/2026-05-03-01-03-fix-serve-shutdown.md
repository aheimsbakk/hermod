---
when: 2026-05-03T01:03:45Z
why: SIGINT on serve raised RuntimeError and left the sweep task pending because loop.stop() aborted run_until_complete mid-flight
what: fix graceful shutdown in serve by cancelling the server task instead of stopping the loop
model: github-copilot/claude-sonnet-4.6
tags: [fix, cli, shutdown, asyncio, serve]
---

Replaced `loop.stop()` with `task.cancel()` in the `serve` signal handler
(`src/hermod/cli/main.py`). The signal handler is now registered inside an
`_main()` coroutine that wraps `run_server` in an `asyncio.Task`; cancelling
the task lets `run_server`'s `finally` blocks run cleanly (server close,
DB close, sweep-task cancel), eliminating the `RuntimeError: Event loop stopped
before Future completed` traceback and the `Task was destroyed but it is pending`
warning. Confirmed `trust`, `tx`, and `rx` only call `logger.exception` for
truly unexpected errors — all expected conditions (wrong channel, connection
refused, invalid code, cert fetch failure) exit cleanly without a traceback.
Bumped to v0.3.7.
