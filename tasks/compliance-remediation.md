# Compliance Remediation

Audit date: 2026-06-20. Source: `.opencode/RULES.md`, `AGENTS.md`.

## Critical

### CI/CD conflict (AGENTS.md — No `.github` workflows)

`AGENTS.md` states "No `.github` workflows." The file `.github/workflows/release.yml` exists.

**Remediation**: Either update `AGENTS.md` to permit CI/CD on tag push, or delete the workflow file.

### Files exceeding 300-line hard limit (Rule III.17)

Eight files exceed the 300-line limit. Rule III.17 states: "Any file that exceeds 300 lines MUST be split immediately. Exception: data schemas, test suites, and configuration files." None of these qualify for the exception.

| File | Lines | Exceeds by |
|------|-------|------------|
| `internal/cli/tx.go` | 875 | +575 |
| `internal/cli/rx.go` | 673 | +373 |
| `internal/crypto/crypto.go` | 746 | +446 |
| `internal/server/server.go` | 625 | +325 |
| `internal/network/network.go` | 455 | +255 |
| `internal/network/signaling.go` | 359 | +159 |
| `internal/crypto/hash_to_curve.go` | 345 | +145 |
| `internal/config/config.go` | 342 | +142 |

## High

### DRY violation (Rule III.18)

`tx.go` and `rx.go` share a ~20-line config-loading block duplicated verbatim:

```go
ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()
logDebug("loading config")
cfg, err := config.Load()
if saveServer && serverURL != cfg.ServerURL {
    config.SetDefaultServer(cfg, serverURL)
    if err := config.Save(cfg); err != nil { ... }
    printStatus("Default server set to %s", serverURL)
    logInfo("Default server updated", "server", serverURL)
}
```

All other shared logic (`generateEphemeralCert`, `channelIDAad`, `holePunchNonce`, `performSASCoordinated`, `buildTLSCert`) is already extracted.

### Silent error discards in teardown paths (Rule III.11)

The following discard errors with `_ =` in error/teardown contexts. These are not empty catch blocks (errors are handled at the call site), but they do not re-throw or log:

| File | Line | Context |
|------|------|---------|
| `server.go` | 229 | HTTP response write in `handleCert` |
| `server.go` | 560 | WriteJSON in `dropChannel` |
| `server.go` | 562 | DeleteChannel in `dropChannel` |
| `udp_reflect.go` | 172 | UDP write in `serve` |
| `udp_reflect.go` | 193 | UDP write in `writeAddress` |

These are acceptable in teardown paths where the primary operation already failed, but worth noting.

## Medium

### .gitignore gaps (Rule IV.20)

Missing Go-relevant patterns:
- `*.exe` — Windows build artifacts
- `*.test` — Go test binaries (compiled with `-c`)
- `*.a` — Go archive files

### .gitignore missing venv/.venv patterns

Rule IV.20 requires virtual environment directories to be in `.gitignore`. Not present.

### Commit format (Conventional Commits)

10/30 recent commits (33%) fail Conventional Commits format. Enforce `<type>(<scope>): <summary>` with types: feat/fix/docs/refactor/test/chore/perf.

### Linter version pinning

`lint_test.go` uses `deadcode@latest` and `staticcheck@latest`. Pin to explicit versions per Rule 23.

### Scripts in README

Rule 24 requires documenting each script in `scripts/` (purpose, args, examples) in `README.md`. Currently only `bump-version.sh` is mentioned.

### demo.gif

488 KB binary tracked in git without LFS. Move to release assets or add to `.gitignore`.

## Low

### Error discard in lint test

`lint_test.go:48` — `cmd.CombinedOutput()` error is silently discarded.

### HTTP timeout

No explicit read/write timeout on `http.Server` in `internal/server/server.go`.

### todo.txt tracked

Personal task file in git; consider ignoring it.

### History bloat

`demo.cast` (144 KB) exists in commit history.
