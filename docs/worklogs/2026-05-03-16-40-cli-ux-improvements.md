---
when: 2026-05-03T16:40:54Z
why: improve CLI discoverability and reduce noise with saner defaults and cleaner help output
what: CLI UX — alias consolidation, effective defaults in help, --listen flag, no-args usage display
model: github-copilot/claude-sonnet-4.6
tags: [cli, ux, typer, help, aliases, verbosity, p2p-listen]
---

Rewrote `src/hermod/cli/main.py` with five UX improvements bumped to v0.6.4: (1) `_AliasedGroup(TyperGroup)` collapses `send`/`tx` and `receive`/`rx` into single help lines (`send or tx`, `receive or rx`); (2) `ctx.default_map` in the group callback injects config-sourced defaults so every subcommand `--help` shows the effective value; (3) `--verbosity` default changed to `"error"` (silent by default); (4) `--p2p-port/-P` renamed to `--listen/-l` on `send`/`receive`, accepting `host:port`, `[ipv6]:port`, or bare `:port`; (5) `ctx.invoked_subcommand is None` check prints usage when called with no subcommand. `src/hermod/core/session.py` gained `p2p_host: str = "0.0.0.0"` on both `SenderSession` and `ReceiverSession`. `CONTEXT.md` and `BLUEPRINT.md` updated to reflect renamed flag and new CLI architecture.
