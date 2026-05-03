---
when: 2026-05-03T18:59:37Z
why: Replace third-party CLI framework with stdlib argparse to reduce supply-chain attack surface.
what: Refactor CLI from Typer + Click to stdlib argparse
model: opencode/claude-sonnet-4-6
tags: [refactor, cli, dependencies, security]
---

Removed `typer` and `click` from `pyproject.toml` and rewrote `src/hermod/cli/main.py` to use `argparse.ArgumentParser` with `add_subparsers`. Aliases (`tx`, `rx`) use the `aliases=` parameter on `add_parser`; `typer.Exit` replaced by `sys.exit`; config-injected defaults baked into `default=` arguments at parser build time; entry point changed from `app` to `main`. `BLUEPRINT.md` and `CONTEXT.md` updated to reflect the new CLI framework. All 208 tests pass. Bumped to v0.8.1.
