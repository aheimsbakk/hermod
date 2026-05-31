---
when: 2026-05-31T10:37:53Z
why: audit reference codes must not appear in user-facing output
what: remove (L-05) audit tag from trust --fingerprint flag description
model: github-copilot/claude-sonnet-4.6
tags: [cli, security-audit, ux]
---

Removed the `(L-05)` security-audit reference from the `--fingerprint` flag help text in `trust.go` — it was visible in `hermod trust --help`. All other `C-XX`, `M-XX`, `L-XX`, `H-XX` references are confined to code comments and are not affected. Bumped to v0.10.1.
