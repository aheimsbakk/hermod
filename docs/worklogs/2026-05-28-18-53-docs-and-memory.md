---
when: 2026-05-28T18:53:48Z
why: Documentation was stale after v0.2.0 code changes
what: Fix README/BLUEPRINT gaps and encode docs-with-code rule
model: github-copilot/claude-sonnet-4.6
tags: [docs, memory, agents, readme, blueprint]
---

Fixed BLUEPRINT.md (version 0.1.0 → 0.2.0, added verbosity.go to file map) and README.md (added --verbose flag to tx/rx/serve tables, documented HERMOD_SERVER and HERMOD_DEST_DIR env vars). Added "Docs with Code" rule to AGENTS.md requiring docs to be updated in the same commit as code. Created docs/memory/ store with an index entry reinforcing the same rule for future sessions. Bumped to v0.2.1.
