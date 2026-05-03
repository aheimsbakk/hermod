---
when: 2026-05-03T11:33:18Z
why: Users had no way to check which version of hermod was installed
what: add --version / -V flag to the CLI
model: github-copilot/claude-sonnet-4.6
tags: [feature, cli, version]
---

Added `--version` / `-V` option to the global `@app.callback()` in `cli/main.py` using `importlib.metadata.version("hermod-p2p")`. The callback is marked `invoke_without_command=True` so the eager flag fires before Typer demands a subcommand. Bumped to v0.5.2.
