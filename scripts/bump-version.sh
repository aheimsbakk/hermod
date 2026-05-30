#!/usr/bin/env bash
# scripts/bump-version.sh — bump VERSION file by patch, minor, or major.
# Updates all version references: VERSION, BLUEPRINT.md.
# Usage: scripts/bump-version.sh [patch|minor|major]
set -euo pipefail

LEVEL="${1:-patch}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION_FILE="$REPO_ROOT/VERSION"
BLUEPRINT_FILE="$REPO_ROOT/BLUEPRINT.md"

current="$(cat "$VERSION_FILE" | tr -d '[:space:]')"

IFS='.' read -r major minor patch <<<"$current"

case "$LEVEL" in
major)
	major=$((major + 1))
	minor=0
	patch=0
	;;
minor)
	minor=$((minor + 1))
	patch=0
	;;
patch) patch=$((patch + 1)) ;;
*)
	echo "Usage: $0 [patch|minor|major]" >&2
	exit 1
	;;
esac

new="$major.$minor.$patch"

# Update VERSION file.
echo "$new" >"$VERSION_FILE"

# Update version reference in BLUEPRINT.md.
sed -i "s/current version ($current)/current version ($new)/" "$BLUEPRINT_FILE"

echo "Bumped $current -> $new"
