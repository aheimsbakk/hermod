# Compliance Remediation

Audit date: 2026-06-20. Source: `.opencode/RULES.md`, `AGENTS.md`.

## Critical

- **CI/CD conflict**: `AGENTS.md` forbids GitHub Actions; `.github/workflows/release.yml` exists.
  Either update `AGENTS.md` to permit CI/CD on tag push, or delete the workflow file.

## High — SRP violations (files exceed 250 lines or mix concerns)

| File | Lines | Action |
|------|-------|--------|
| `internal/cli/tx.go` | 874 | Split presentation (progress bars, SAS prompts) from transport logic |
| `internal/cli/rx.go` | 669 | Same as tx.go |
| `internal/crypto/crypto.go` | 746 | Split by protocol component (CPace, OPRF, OPBEF, key exchange, AES-GCM) |
| `internal/server/server.go` | 626 | Split WebSocket handler, relay, blob storage into separate files |
| `internal/network/network.go` | 417 | Split QUIC dial/listen, packet mux, helpers |
| `internal/network/signaling.go` | 359 | Split signaling protocol from relay/blob transfer |

## Medium

- **Commit format**: 10/30 recent commits (33%) fail Conventional Commits format.
  Enforce `<type>(<scope>): <summary>` with types: feat/fix/docs/refactor/test/chore/perf.
- **Linter version pinning**: `lint_test.go` uses `deadcode@latest` and `staticcheck@latest`.
  Pin to explicit versions per Rule 23.
- **Scripts in README**: Rule 24 requires documenting each script in `scripts/` (purpose, args, examples) in `README.md`. Currently only `bump-version.sh` is mentioned.
- **demo.gif**: 488 KB binary tracked in git without LFS. Move to release assets or add to `.gitignore`.

## Low

- **Error discard**: `lint_test.go:48` — `cmd.CombinedOutput()` error is silently discarded.
- **HTTP timeout**: No explicit read/write timeout on `http.Server` in `internal/server/server.go`.
- **todo.txt tracked**: Personal task file in git; consider ignoring it.
- **History bloat**: `demo.cast` (144 KB) exists in commit history.
