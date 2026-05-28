#!/usr/bin/env bash
# scripts/bump-version.sh — bump VERSION file by patch, minor, or major.
# Usage: scripts/bump-version.sh [patch|minor|major]
set -euo pipefail

LEVEL="${1:-patch}"
VERSION_FILE="$(dirname "$0")/../VERSION"
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
echo "$new" >"$VERSION_FILE"
echo "Bumped $current -> $new"
