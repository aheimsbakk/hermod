---
when: 2026-05-28T20:10:21Z
why: Output had an unwanted blank line before the SAS verification header
what: Remove leading newline from Out-of-Band Verification output
model: github-copilot/claude-sonnet-4.6
tags: [fix, cli, ux]
---

Removed the leading `\n` from the `=== Out-of-Band Verification ===` fprintf in `internal/cli/tx.go` so no blank line appears between "Establishing P2P connection..." and the verification block. Also includes pre-existing changes to skill descriptions and AGENTS.md rule cleanup. Bumped to v0.2.3.
