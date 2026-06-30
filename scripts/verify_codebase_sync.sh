#!/usr/bin/env bash
# scripts/verify_codebase_sync.sh — validate CODEBASE.md against the physical tree.
#
# Checks that every path referenced in CODEBASE.md exists on disk, that every
# *_test.go file on disk is listed in the Test File Inventory, and that the
# version string in CODEBASE.md matches the VERSION file.
#
# Usage: scripts/verify_codebase_sync.sh
# Exit status: 0 if synced, 1 if drift is detected.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CODEBASE="$REPO_ROOT/CODEBASE.md"
VERSION_FILE="$REPO_ROOT/VERSION"

if [[ ! -f "$CODEBASE" ]]; then
	echo "error: CODEBASE.md not found at $CODEBASE" >&2
	exit 1
fi

if [[ ! -f "$VERSION_FILE" ]]; then
	echo "error: VERSION file not found at $VERSION_FILE" >&2
	exit 1
fi

drift=0

# --- 1. Verify physical paths referenced in CODEBASE.md ----------------------
#
# Extract path tokens from the annotated tree (lines starting with ├── or └──
# inside a fenced block) and from backtick-quoted paths in mapping tables.
# Strip trailing wildcards and inline comments.
extract_paths() {
	awk '
		/^```/ { in_fence = !in_fence; next }
		in_fence && (/^[[:space:]]*[├└]── /) {
			line = $0
			sub(/^[[:space:]]*[├└]── /, "", line)
			sub(/  #.*$/, "", line)
			sub(/ #.*$/, "", line)
			gsub(/[[:space:]]+$/, "", line)
			if (line != "") print line
		}
	' "$CODEBASE"

	# Backtick-quoted paths in tables and prose. Keep only tokens that look
	# like repo-relative paths (contain a slash or a known source suffix).
	grep -oE '`[^`]+`' "$CODEBASE" |
		tr -d '`' |
		grep -E '^([A-Za-z0-9._-]+/|[A-Za-z0-9._-]+\.(go|md|sh|yml|yaml|mod|sum|txtar|gif))$' ||
		true
}

# Resolve wildcards (e.g. e2e/testdata/scripts/*.txtar) by globbing; if a
# literal path does not exist, report it.
while IFS= read -r raw; do
	[[ -z "$raw" ]] && continue
	# Skip entries that are clearly not file paths (no extension, no slash).
	case "$raw" in
	*.txtar | *.go | *.md | *.sh | *.yml | *.yaml | *.mod | *.sum | *.gif) ;;
	*/*) ;;
	*) continue ;;
	esac

	# Expand globs relative to repo root.
	shopt -s nullglob
	matches=()
	# shellcheck disable=SC2206
	matches=($REPO_ROOT/$raw)
	shopt -u nullglob

	if [[ ${#matches[@]} -eq 0 ]] && [[ ! -e "$REPO_ROOT/$raw" ]]; then
		echo "orphaned path in CODEBASE.md (not on disk): $raw"
		drift=1
	fi
done < <(extract_paths | sort -u)

# --- 2. Verify every *_test.go file is listed in CODEBASE.md -----------------
while IFS= read -r -d '' testfile; do
	rel="${testfile#$REPO_ROOT/}"
	if ! grep -qF "$rel" "$CODEBASE"; then
		echo "test file missing from CODEBASE.md inventory: $rel"
		drift=1
	fi
done < <(find "$REPO_ROOT" -name '*_test.go' -not -path '*/.git/*' -print0)

# --- 3. Verify VERSION consistency -------------------------------------------
version_file_value="$(tr -d '[:space:]' <"$VERSION_FILE")"

# CODEBASE.md annotates the VERSION entry as: VERSION  # Current version string (x.y.z)
version_doc_value="$(grep -oE 'VERSION +# Current version string \([0-9]+\.[0-9]+\.[0-9]+\)' "$CODEBASE" 2>/dev/null | grep -oE '\([0-9]+\.[0-9]+\.[0-9]+\)' | tr -d '()' || true)"
if [[ -z "$version_doc_value" ]]; then
	echo "could not locate VERSION annotation in CODEBASE.md"
	drift=1
elif [[ "$version_file_value" != "$version_doc_value" ]]; then
	echo "version drift: VERSION file=$version_file_value  CODEBASE.md=$version_doc_value"
	drift=1
fi

# --- 4. Verify audits listed in CODEBASE.md exist on disk --------------------
#
# CODEBASE.md lists audits by basename inside the annotated tree, so match by
# filename rather than full relative path.
audit_dir="$REPO_ROOT/docs/audits"
if [[ -d "$audit_dir" ]]; then
	for f in "$audit_dir"/*.md; do
		[[ -e "$f" ]] || continue
		base="$(basename "$f")"
		if ! grep -qF "$base" "$CODEBASE"; then
			echo "audit file missing from CODEBASE.md: docs/audits/$base"
			drift=1
		fi
	done
fi

if [[ $drift -ne 0 ]]; then
	echo "error: CODEBASE.md is out of sync with the repository (see above)" >&2
	exit 1
fi

echo "CODEBASE.md is in sync with the repository."
