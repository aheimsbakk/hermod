---
when: 2026-05-03T11:37:52Z
why: The _SuppressTrustProbe filter only checked record.getMessage() but websockets logs "opening handshake failed" as the top-level message with the EOFError buried in the exception chain
what: fix _SuppressTrustProbe to walk the exception chain so the trust-probe noise is actually suppressed
model: github-copilot/claude-sonnet-4.6
tags: [bugfix, server, logging, trust]
---

`_SuppressTrustProbe.filter()` in `server/signaling.py` now walks `exc.__cause__` / `exc.__context__` to find the `EOFError: connection closed while reading HTTP request line` that websockets attaches as a chained exception, rather than only checking `record.getMessage()`. Added five regression tests in `tests/test_server.py` covering direct message match, single-level cause, two-level cause, unrelated error pass-through, and no-exc_info pass-through. Bumped to v0.5.3.
