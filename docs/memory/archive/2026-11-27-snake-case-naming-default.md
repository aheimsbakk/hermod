---
topic: "snake_case is the project naming default"
importance: high
category: decision
tags: [naming, snake-case, conventions, scripts]
created: 2026-11-27T22:35:00Z
model: kompis/qwen3.8-flash-next-iq3_s
---

The user chose snake_case as the default file/directory naming convention;
it is declared in `AGENTS.md` (satisfying RULES.md rule 10's override
mechanism) and detailed in `CODEBASE.md`. The scripts in `scripts/` were
renamed from kebab-case to snake_case (`build_release.sh`,
`bump_version.sh`, `check_coverage.sh`, `extract_changelog_entry.sh`,
`validate_changelog.sh`). Historical kebab-case prose docs under `docs/`
and `tasks/` keep their names; new files use snake_case.
