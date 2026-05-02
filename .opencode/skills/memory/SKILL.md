---
name: memory
description: Store and recall persistent context across sessions — user preferences, architectural decisions, recurring patterns, and warnings. Load this skill before recommending tools, frameworks, or patterns; when the user says "remember", "recall", "last time", or references a past session; when the user states a rule or preference; or when a decision worth preserving is reached.
compatibility: opencode
---

## When to write a memory

Write an entry when something is worth keeping for next session:

- **preference** — tooling choices, style rules, workflow habits
- **decision** — why a technology, pattern, or structure was chosen
- **pattern** — a problem or fix worth preserving
- **fact** — useful project info not captured elsewhere
- **warning** — a footgun, deprecated path, or constraint to respect

Skip if it's: single-session debug output, already in `AGENTS.md` / `RULES.md` / `BLUEPRINT.md`, secrets, or prompt text.

---

## Memory file format

Path: `docs/memory/archive/YYYY-MM-DD-<short-slug>.md`

Required front matter: `topic`, `importance` (high/medium/low), `category` (preference/decision/fact/pattern/warning), `tags` (2–5 lowercase keywords; hyphens for multi-word), `created` (ISO 8601 UTC), `model`. Optional: `expires` (ISO 8601 UTC).

Body: 1–4 concrete, actionable sentences. Don't repeat front matter.

```markdown
---
topic: "Vitest preferred over Jest"
importance: high
category: preference
tags: [testing, vitest]
created: 2026-05-01T10:00:00Z
model: github-copilot/claude-sonnet-4.6
---

User prefers Vitest for all unit and integration tests. Run with
`--reporter=verbose`. Avoid snapshots unless explicitly requested.
```

---

## Writing a memory

1. **Check INDEX first.** Read `docs/memory/INDEX.md` (skip if already read this session). Look for an existing row on the same topic or overlapping subject.
   - Conflicts or supersedes existing → **update** (delete old file, remove its row, then write the new one).
   - Adds distinct context → write a new entry.
   - No match → write a new entry.

2. **Get timestamp:** `date -u +"%Y-%m-%dT%H:%M:%SZ"`. Use the date for the filename, full value for `created`.

3. **Write the file** to `docs/memory/archive/YYYY-MM-DD-<2–5-word-slug>.md`.

4. **Append a row to `docs/memory/INDEX.md`:**
   ```
   | <topic> | <category> | <importance> | <tags, comma-separated> | <expires or empty> | archive/<filename> |
   ```
   Without the INDEX row, the entry is invisible to future lookups.

Never overwrite in place — `created` must reflect the current version. Never keep both versions of conflicting entries.

---

## Reading memory

**Decide whether to look:** check memory before recommending tools, architecture, or design; when the user references a past session; or when the task touches a domain where a preference might exist. Otherwise skip — don't read speculatively.

**Look it up:**

1. Read `docs/memory/INDEX.md`. Before matching, prune expired rows: delete the archive file and remove the row for any entry whose `expires` has passed.
2. Find rows where `topic`, `tags`, or `category` match the current task. If nothing matches on the obvious keywords, try related terms once before concluding nothing is stored.
3. Read all matching archive files in a single parallel batch. If a file's `expires` has passed when you read it, delete it and its INDEX row instead of using the content.

**Keyword search fallback** (when the index columns don't capture what you need):

```
Grep pattern="<keyword>" include="docs/memory/archive/*.md"
```

---

## First-time setup

If `docs/memory/INDEX.md` doesn't exist, create the directory and seed the index:

```bash
mkdir -p docs/memory/archive
```

```markdown
# Memory Index

| topic | category | importance | tags | expires | file |
|---|---|---|---|---|---|
```
