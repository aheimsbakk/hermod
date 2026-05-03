---
when: 2026-05-03T12:31:36Z
why: hermod tx was exiting after exactly 30 seconds regardless of --ttl because the PEER_CONNECTED wait used a hardcoded 30-second timeout
what: Fix sender peer-wait timeout — use TTL-derived peer_wait_timeout instead of hardcoded 30s (v0.6.1)
model: github-copilot/claude-sonnet-4.6
tags: [bugfix, session, cli, timeout]
---

`_ws_recv` gained an optional `timeout` parameter (default 30 s for fast
protocol exchanges). `SenderSession` gained `peer_wait_timeout: float = 3600.0`
which is forwarded exclusively to the `PEER_CONNECTED` wait — the only step
driven by a human on the other end. The CLI now passes `cfg.ttl` as
`peer_wait_timeout` so the sender waits as long as the server retains the
channel. A regression test (`test_sender_peer_wait_timeout_respected`) uses a
stall server that never sends `PEER_CONNECTED` and verifies the session exits
in under 5 s with `peer_wait_timeout=0.3`. Version bumped to 0.6.1; all 201
tests pass.

Files touched: `src/hermod/core/session.py`, `src/hermod/cli/main.py`,
`tests/test_session.py`, `pyproject.toml`.
