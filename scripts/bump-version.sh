#!/usr/bin/env bash
# scripts/bump-version.sh
# Bumps the project version in pyproject.toml.
#
# Usage:
#   scripts/bump-version.sh [patch|minor|major]
#
# Example:
#   scripts/bump-version.sh patch   # 0.1.0 → 0.1.1
#   scripts/bump-version.sh minor   # 0.1.0 → 0.2.0
#   scripts/bump-version.sh major   # 0.1.0 → 1.0.0

set -euo pipefail

LEVEL="${1:-patch}"
PYPROJECT="$(dirname "$0")/../pyproject.toml"

if [[ ! -f "$PYPROJECT" ]]; then
	echo "ERROR: pyproject.toml not found at $PYPROJECT" >&2
	exit 1
fi

# Extract current version
CURRENT=$(grep -E '^version = ' "$PYPROJECT" | head -1 | sed 's/version = "\(.*\)"/\1/')
if [[ -z "$CURRENT" ]]; then
	echo "ERROR: Could not extract version from pyproject.toml" >&2
	exit 2
fi

IFS='.' read -r MAJOR MINOR PATCH <<<"$CURRENT"

case "$LEVEL" in
patch) PATCH=$((PATCH + 1)) ;;
minor)
	MINOR=$((MINOR + 1))
	PATCH=0
	;;
major)
	MAJOR=$((MAJOR + 1))
	MINOR=0
	PATCH=0
	;;
*)
	echo "ERROR: Unknown level '$LEVEL'. Use patch, minor, or major." >&2
	exit 3
	;;
esac

NEW="${MAJOR}.${MINOR}.${PATCH}"

# Replace version in pyproject.toml (first occurrence only)
sed -i "0,/^version = \"${CURRENT}\"/s/^version = \"${CURRENT}\"/version = \"${NEW}\"/" "$PYPROJECT"

echo "$NEW"
