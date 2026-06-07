#!/usr/bin/env bash
# scripts/extract-changelog-entry.sh — extract a version entry from CHANGELOG.md.
# Outputs the full markdown entry for the given version, suitable for GitHub
# Release notes.
#
# Usage: scripts/extract-changelog-entry.sh <version> [changelog_file]
#   <version>  Version to extract (with or without leading 'v'), e.g. v0.10.3
#   [changelog_file]  Path to CHANGELOG.md (default: CHANGELOG.md)
#
# Examples:
#   scripts/extract-changelog-entry.sh v0.10.3
#   scripts/extract-changelog-entry.sh 0.10.2
set -euo pipefail

VERSION="${1:?Usage: $0 <version> [changelog_file]}"
CHANGELOG="${2:-CHANGELOG.md}"

if [ ! -f "$CHANGELOG" ]; then
	echo "ERROR: $CHANGELOG not found" >&2
	exit 1
fi

# Strip leading 'v' if present, so we can match both [0.10.3] and [v0.10.3]
VERSION_NUM="${VERSION#v}"

entry="$(
	awk -v ver="$VERSION_NUM" '
    BEGIN { found = 0 }
    /^## \[/ {
      if (found) exit
      # Match heading with [ver] or [vver]
      bracket_ver = "[" ver "]"
      bracket_vver = "[v" ver "]"
      if (index($0, bracket_ver) > 0 || index($0, bracket_vver) > 0) {
        found = 1
        print
        next
      }
    }
    found { print }
  ' "$CHANGELOG"
)"

if [ -z "$entry" ]; then
	echo "ERROR: version ${VERSION} not found in ${CHANGELOG}" >&2
	exit 1
fi

echo "$entry"
