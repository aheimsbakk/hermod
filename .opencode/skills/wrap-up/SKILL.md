---
name: wrap-up
description: Apply end-of-task ceremony for worklogs, version bumping, and git commits. Use when a task is complete and ready for finalization — after the user says "wrap up", "commit", or "done", or when the Builder hands off to QA.
---

## What this skill does

Defines the shared end-of-task procedure: write a worklog, bump the version,
and commit with strict staging rules. Every agent that finalizes work uses
this same process.

---

## 1. Worklog

**Path:** `docs/worklogs/YYYY-MM-DD-HH-mm-{short-desc}.md`

**Date and time:** Use the `date` command to get the current UTC timestamp.

**Front matter (strict):** Must contain ONLY these keys:

```yaml
---
when: 2026-02-14T12:00:00Z  # ISO 8601 UTC
why: one-sentence reason
what: one-line summary
model: model-id (e.g. github-copilot/gpt-4)
tags: [list, of, tags]
---
```

**Body:** 1-4 sentences summarizing changes and files touched. No redundant
info.

**Safety:** No secrets, API keys, or prompt text.

---

## 2. Version bumping

Every finalized feature or bugfix MUST bump the version exactly once per task.

| Change type | Bump | Example |
|---|---|---|
| Bug fix, refactor | Patch (`0.0.x`) | `scripts/bump-version.sh patch` |
| New feature, enhancement | Minor (`0.x.0`) | `scripts/bump-version.sh minor` |
| Breaking change | Major (`x.0.0`) | `scripts/bump-version.sh major` |

**Tool:** Run `scripts/bump-version.sh [patch|minor|major]`.
If the script does not exist, the agent is authorized to create it.

**Rule:** Do NOT bump again when fixing QA failures in the same task. Bump
once only.

**Mention the new version in the worklog body.**

---

## 3. Workspace hygiene

Before committing, ensure the repository is clean:

- Add temporary build artifacts, dependency caches, and error logs (e.g.
  `.qa-error.log`) to `.gitignore`.
- **Never** add source code, configuration files (including `VERSION`), or
  documentation directories (including `docs/worklogs/`) to `.gitignore`.
  These must remain tracked by Git.

---

## 4. Git commit protocol

### Staging rules

- **Targeted staging only.** Use `git add <path/to/file1> <path/to/file2>`.
- **Forbidden:** `git add .`, `git commit -a`, and any wildcard staging.
- Stage only the specific files modified in this task, plus architecture
  files (`BLUEPRINT.md`, `CONTEXT.md`, `docs/PROJECT_RULES.md`) if they
  show as modified in `git status`.

### Pre-commit verification

1. Run `git status` and inspect the output.
2. If temporary files (e.g. `.qa-error.log`) are staged, run `git reset`
   to unstage them.
3. Confirm the staging area contains exactly the intended files.

### Commit message

Use Conventional Commits format and reference the new version:

```
<type>(<scope>): <short summary>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

---

## 5. Execution sequence

Run these steps in order:

1. Workspace hygiene (update `.gitignore`)
2. Version bump (`scripts/bump-version.sh`)
3. Write the worklog (`docs/worklogs/`)
4. Run validation (`scripts/validate-worklog.sh`). If the script does not exist, the agent is authorized to create it.
5. Stage files explicitly (`git add <file> ...`)
6. Verify staging (`git status`)
7. Commit (`git commit -m "<message>"`)
