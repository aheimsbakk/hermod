#!/usr/bin/env bash
# scripts/validate-worklog.sh — validate YAML front matter in a worklog file.
# Usage: scripts/validate-worklog.sh <path-to-worklog.md>
set -euo pipefail

FILE="${1:-}"
if [[ -z "$FILE" ]]; then
	echo "Usage: $0 <worklog.md>" >&2
	exit 1
fi

for key in when why what model tags; do
	if ! grep -q "^${key}:" "$FILE"; then
		echo "ERROR: missing front-matter key: $key" >&2
		exit 1
	fi
done

echo "Worklog OK: $FILE"
