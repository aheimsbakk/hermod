---
when: 2026-05-03T08:41:32Z
why: Add the universal -h shorthand for --help alongside the existing --help flag
what: Add -h/--help alias to all CLI commands; remap serve --host to -H
model: github-copilot/claude-sonnet-4.6
tags: [cli, ux, patch]
---

Added `context_settings={"help_option_names": ["-h", "--help"]}` to the root `typer.Typer` app so `-h` triggers help on the root command and all subcommands. Renamed `serve`'s conflicting `-h` short option for `--host` to `-H` to free the flag. Updated `BLUEPRINT.md` §22 to reflect the `-H` change. Bumped to v0.4.1.
