---
topic: "GitHub release workflow is the only allowed CI workflow"
importance: high
category: decision
tags: [ci-cd, github-workflows, exception, release]
created: 2026-11-27T22:17:46Z
model: kompis/qwen3.8-flash-next-iq3_s
---

The user restored `.github/workflows/release.yml` and amended `AGENTS.md`
so this single workflow is an explicit exception to the "no `.github`
workflows" rule. Do not delete or add any other workflows; release
automation for `vX.Y.Z` tags stays in this workflow.
