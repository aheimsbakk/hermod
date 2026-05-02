#!/usr/bin/env bash
# scripts/validate-worklog.sh
# Validates that all worklog files under docs/worklogs/ conform to the
# required YAML front-matter schema.
#
# Usage:
#   scripts/validate-worklog.sh
#
# Exit codes:
#   0 – all worklogs valid
#   1 – one or more worklogs invalid

set -euo pipefail

WORKLOG_DIR="$(dirname "$0")/../docs/worklogs"
ERRORS=0

if [[ ! -d "$WORKLOG_DIR" ]]; then
	echo "No worklogs directory found; skipping."
	exit 0
fi

REQUIRED_KEYS=(when why what model tags)

for FILE in "$WORKLOG_DIR"/*.md; do
	[[ -f "$FILE" ]] || continue
	BASENAME=$(basename "$FILE")

	# Check filename format: YYYY-MM-DD-HH-mm-{short-desc}.md
	if ! echo "$BASENAME" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-.+\.md$'; then
		echo "FAIL [$BASENAME]: filename does not match YYYY-MM-DD-HH-mm-{desc}.md"
		ERRORS=$((ERRORS + 1))
		continue
	fi

	for KEY in "${REQUIRED_KEYS[@]}"; do
		if ! grep -qE "^${KEY}:" "$FILE"; then
			echo "FAIL [$BASENAME]: missing front-matter key '${KEY}'"
			ERRORS=$((ERRORS + 1))
		fi
	done

	echo "OK   [$BASENAME]"
done

if [[ $ERRORS -gt 0 ]]; then
	echo ""
	echo "Worklog validation failed with $ERRORS error(s)."
	exit 1
fi

echo ""
echo "All worklogs valid."
exit 0
