---
when: 2026-05-30T22:16:40Z
why: plain go build was showing "dev" instead of the real version number
what: add version.go with embedded appVersion constant; update bump-version.sh to keep it in sync
model: github-copilot/claude-sonnet-4.6
tags: [cli, version, fix]
---

Added `internal/cli/version.go` containing `const appVersion = "0.9.0"`, used as the default value for the `Version` variable in `root.go`. A plain `go build ./cmd/hermod/` now produces the correct version without requiring `-ldflags`. Updated `scripts/bump-version.sh` to patch the constant in `version.go` alongside `VERSION` and `BLUEPRINT.md` on every bump. No logic changes; all existing tests pass.
