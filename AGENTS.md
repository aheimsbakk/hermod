# Master Rules

- ALWAYS read `.opencode/RULES.md` alongside this file. Both are required.

Coding workflows: architecture -> implementation -> testing -> zero problems -> wrap-up.

## General Rules

- **No CI/CD:** Do not create GitHub Actions or any CI/CD under `.github`.
- **Commit Messages:** Use Conventional Commits format for all commits: `<type>(<scope>): <short summary>`. Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`. Reference the version when bumping (e.g. `chore(release): bump to v1.2.0`).

## Documentation Files

- **Structure:** `./BLUEPRINT.md` = Current Architecture, Data Models. `./CONTEXT.md` = Overview, Dependencies. Keep all brutally short.
- **No Coding or Pseudocode:** `BLUEPRINT.md`, `CONTEXT.md`, and `PROJECT_RULES.md` must NEVER contain application source code, pseudocode, algorithmic logic, scripts, or config files. Write only high-level concepts, file paths, schemas, and API signatures.
- **Project Rules Limits:** `./docs/PROJECT_RULES.md` must have MAX 5 non-redundant, short actionable rules. No tutorials or explanations.
