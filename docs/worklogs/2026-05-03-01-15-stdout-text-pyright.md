---
when: 2026-05-03T01:15:29Z
why: deliver stdout-for-text, original-filename, stderr SAS, and zero pyright errors
what: v0.4.0 — text rx to stdout, file rx with original name, pyright clean
model: github-copilot/claude-sonnet-4.6
tags: [session, receiver, cli, pyright, types]
---

Added `text_content: str | None` to `TransferResult` and split `_receive_payload` into `_receive_text` (in-memory, returns `text_content`) and `_receive_file` (streams to disk under original filename). CLI `rx` writes `text_content` to `sys.stdout`; file saves continue to print "Saved to …" on stderr. SAS `print()` calls in `session.py` redirected to `sys.stderr`. Introduced `pyrightconfig.json` (venv-aware, standard mode) and fixed three source-level type errors (`asyncio` import in `wire.py`, optional narrowing in `db.py`, `msgpack.packb` assert in `session.py` and `signaling.py`); pyright now reports 0 errors. Bumped to v0.4.0.
