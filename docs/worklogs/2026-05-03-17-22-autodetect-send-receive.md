---
when: 2026-05-03T17:22:01Z
why: Remove explicit --file/--text flags in favour of ergonomic auto-detection on send, and add stdout-streaming mode on receive for Unix piping
what: Refactor send/receive CLI to auto-detect payload type and stream to stdout when redirected
model: github-copilot/claude-sonnet-4.6
tags: [cli, ux, refactor, session, streaming]
---

Replaced `--file/-f` and `--text/-t` on `hermod send` with a single positional `[INPUT]` argument: existing path → file, plain string → text, `-` or piped stdin → UTF-8-decodable bytes become text, non-UTF-8 bytes become a binary file named "stdin". `SenderSession` gains a `raw_bytes` parameter and `_send_raw_bytes` method for the binary stdin path. `hermod receive --destination` is now optional; when stdout is redirected or piped, all payload bytes (text or file) stream directly to `sys.stdout.buffer` via a new `output_sink` parameter and `_stream_file_to_sink` method on `ReceiverSession`. Four new session integration tests added; 208/208 passing. Bumped to v0.7.0. Files touched: `src/hermod/cli/main.py`, `src/hermod/core/session.py`, `tests/test_session.py`, `BLUEPRINT.md`, `CONTEXT.md`.
