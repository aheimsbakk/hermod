---
when: 2026-05-03T12:04:19Z
why: Consolidate all persistent state into a single config.yaml, replacing the separate trust_store.json file and the split host/port config fields
what: Config consolidation — listen field, trusted_servers in config.yaml, serve --listen, trust auto-saves server URL (v0.6.0)
model: github-copilot/claude-sonnet-4.6
tags: [config, trust, cli, refactor, minor]
---

Replaced the separate `~/.hermod/trust_store.json` with a `trusted_servers` mapping
inside `~/.config/hermod/config.yaml`, making it the sole persistent store for all
settings including pinned certificates. The `host`/`port` dataclass fields were merged
into a single `listen: str` field with `parse_listen`/`format_listen` helpers supporting
both IPv4 and bracketed IPv6 notation. The `serve` command now accepts `--listen/-l`
(replaces `--host/-H` + `--port/-p`), and `trust` additionally saves the pinned server
as the config default. `TrustStore` constructor argument renamed from `path` to
`config_path`. Version bumped to 0.6.0; all 200 tests pass.

Files touched: `src/hermod/core/config.py`, `src/hermod/core/trust.py`,
`src/hermod/cli/main.py`, `tests/test_config.py`, `tests/test_session.py`,
`BLUEPRINT.md`, `CONTEXT.md`, `pyproject.toml`.
