# Master Rules

- ALWAYS read `.opencode/RULES.md` alongside this file. Both are required.

Coding workflows: architecture -> implementation -> testing -> zero problems -> wrap-up.

## General Rules

- **No CI/CD:** Do not create GitHub Actions or any CI/CD under `.github`.
- **Commit Messages:** Use Conventional Commits format for all commits: `<type>(<scope>): <short summary>`. Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`. Reference the version when bumping (e.g. `chore(release): bump to v1.2.0`).

## BLUEPRINT.md Generation Directives

Generate a language-agnostic, domain-agnostic architecture document providing deterministic specifications for downstream implementation.

- **Required Sections:** Define System Goals, Logical Component Hierarchy, Data Flow Sequences, and State/Memory Management strategy.
- **Interface Contracts:** Specify system entry points (e.g., Network API, CLI args, IPC, UI events) with strict input/output payload schemas and error boundaries.
- **Data & Persistence:** Define abstract schemas (relational entities, file structures, memory layouts), constraints, and state tree configurations.
- **Dependencies & Security:** Specify environment configuration requirements, authorization flows, and external hardware/service integrations.
- **Prohibited Elements:** NO executable source code. NO framework-specific configurations. NO language-tied directory structures.
- **Allowed Logic:** Utilize abstract state machine rules or generic sequential steps. Do not use language-specific pseudocode.
