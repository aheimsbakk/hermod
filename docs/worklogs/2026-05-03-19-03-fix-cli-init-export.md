---
when: 2026-05-03T19:03:29Z
why: cli/__init__.py still exported the old `app` symbol after the Typer-to-argparse refactor, causing an ImportError at startup.
what: Fix cli/__init__.py to export main instead of app
model: opencode/claude-sonnet-4-6
tags: [fix, cli]
---

Updated `src/hermod/cli/__init__.py` to re-export `main` instead of the removed `app` symbol. All 208 tests pass. Bumped to v0.8.2.
