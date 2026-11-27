# Contributing to Hermod

This guide covers development setup, build and test commands, utility
scripts, and the release workflow. User documentation lives in `README.md`.

## Prerequisites

- Go 1.25.0 or newer
- Linux, macOS, or Windows

No global tool installs are required. Lint tools (deadcode, staticcheck)
run through `go test` and are downloaded at a pinned version.

## Build

```bash
go build -o hermod ./cmd/hermod/
```

Embed the release version string at build time:

```bash
go build -ldflags "-X github.com/hermod/hermod/internal/cli.Version=$(cat VERSION)" -o hermod ./cmd/hermod/
```

## Test

```bash
# Run all tests (includes the dead-code and staticcheck lint suite)
go test ./...

# Run with coverage
go test -coverprofile=cover.out ./...
go tool cover -html=cover.out
```

All packages target at least 80% test coverage. Enforce it with
`scripts/check_coverage.sh`.

To skip the lint suite during fast iteration, set `HERMOD_SKIP_LINT=1`:

```bash
HERMOD_SKIP_LINT=1 go test ./...
```

The lint tools are pinned in `lint_test.go`
(`golang.org/x/tools/cmd/deadcode@v0.45.0`,
`honnef.co/go/tools/cmd/staticcheck@v0.8.2`). Bump both pins deliberately,
never to `latest`.

## Utility scripts

All scripts live in `scripts/` and are executable.

### build_release.sh

Cross-compiles one release binary into `dist/`.

```bash
scripts/build_release.sh linux amd64          # -> dist/hermod-linux-amd64
scripts/build_release.sh windows arm64 out/   # -> out/hermod-windows-arm64.exe
```

Arguments: `<os> <arch> [output_dir]`. Supported OS values: linux,
windows, darwin.

### bump_version.sh

Bumps the version by `patch`, `minor`, or `major` and syncs every version
reference: the `VERSION` file, `BLUEPRINT.md`, and
`internal/cli/version.go`.

```bash
scripts/bump_version.sh patch
```

### check_coverage.sh

Runs per-package coverage and fails if any required package falls below
the 80% threshold.

```bash
scripts/check_coverage.sh
```

### extract_changelog_entry.sh

Prints the `CHANGELOG.md` entry for one version as markdown, suitable for
release notes.

```bash
scripts/extract_changelog_entry.sh 1.2.0
scripts/extract_changelog_entry.sh 1.2.0 CHANGELOG.md
```

### validate_changelog.sh

Validates that `CHANGELOG.md` exists and follows the Keep a Changelog
structure.

```bash
scripts/validate_changelog.sh
```

### verify_codebase_sync.sh

Validates `CODEBASE.md` against the physical tree: every referenced path
exists, every `*_test.go` file on disk appears in the Test File Inventory,
and the version string in `CODEBASE.md` matches the `VERSION` file.

```bash
scripts/verify_codebase_sync.sh
```

## Release workflow

1. Run the tests and the verification gate:
   `go test ./... && scripts/check_coverage.sh &&
   scripts/validate_changelog.sh && scripts/verify_codebase_sync.sh`
2. Bump the version: `scripts/bump_version.sh <patch|minor|major>`.
3. Add the release entry to `CHANGELOG.md`, then validate it with
   `scripts/validate_changelog.sh`.
4. Push the version tag:
   ```bash
   git tag vX.Y.Z
   git push --follow-tags
   ```
   `.github/workflows/release.yml` triggers on `vX.Y.Z` tags. It builds
   linux/amd64, linux/arm64, windows/amd64, windows/arm64, and darwin/arm64
   and publishes a GitHub Release with the changelog entry and checksums.
   This is the only CI workflow permitted — see the exception in
   `AGENTS.md`.
5. For local builds only, run `scripts/build_release.sh <os> <arch>`;
   binaries land in `dist/`.

## Commit conventions

Use Conventional Commits: `<type>(<scope>): <summary>`. Summary lines stay
under 50 characters and use the imperative mood ("add", "fix", "remove").
Documentation-sync commits use `docs(sync):` and must precede the feature
or fix commit they accompany.

## Documentation duties

- `README.md` holds user documentation only; developer guides live here.
- `BLUEPRINT.md` holds the language-agnostic architecture; `CODEBASE.md`
  maps it to physical files. Update both when architecture or file layout
  changes, then run `scripts/verify_codebase_sync.sh`.
- Update `CHANGELOG.md` under the Unreleased section for every user-facing
  change.
