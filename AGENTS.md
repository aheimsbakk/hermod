# Master Rules

- ALWAYS read `.opencode/RULES.md` alongside this file. Both are required.

Coding workflows: architecture -> implementation -> testing -> zero problems -> wrap-up.

## General Rules

- **No CI/CD:** Do not create GitHub Actions or any CI/CD under `.github`.
- **Commit Messages:** Use Conventional Commits format for all commits: `<type>(<scope>): <short summary>`. Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`. Reference the version when bumping (e.g. `chore(release): bump to v1.2.0`).

## Documentation Files

- **Structure:** `./BLUEPRINT.md` = Language-agnostic system design, core data models, and architecture. Define system goals, logical components, system interactions, and key architectural decisions. Keep it concise.
- **No Implementation Details:** `BLUEPRINT.md` must NEVER contain application source code, pseudocode, algorithmic logic, framework configurations, or language-specific file directories.
- **Allowed Abstractions:** Document only high-level domain boundaries, abstract data schemas (e.g., relational models or JSON schemas), and system-to-system interface contracts (inputs/outputs). The architecture must remain fully executable in any programming language.
