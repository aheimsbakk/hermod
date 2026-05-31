---
when: 2026-05-30T14:45:15Z
why: four user-reported UX improvements to rx output, serve startup, version flag, and receive confirmation
what: fix rx blank line, add serve fingerprint output, add --version/-V flag, add rx completion message
model: github-copilot/claude-sonnet-4.6
tags: [cli, ux, rx, serve, version]
---

Fixed four UX issues across the CLI. In `rx.go`: removed the extra blank line after the progress bar for file transfers (stripped leading `\n` from `printStatus`), and replaced `fmt.Fprintln(os.Stderr)` with `fmt.Fprint(os.Stdout, "\n")` so text output ends cleanly on stdout. Added `printStatus("Receive and verification complete.")` on successful receive and a user-facing error message on hash mismatch. In `serve.go`: startup now prints the server certificate fingerprint so operators can share it. In `root.go`: added `Version` package variable (set via `-ldflags`) and wired it to cobra's built-in `--version` plus a `-V` short alias. Updated `scripts/bump-version.sh` to also patch the version in `BLUEPRINT.md`, and updated `README.md` with ldflags build instructions. Bumped to v0.9.0.
