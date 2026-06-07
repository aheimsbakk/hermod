#!/usr/bin/env bash
# scripts/validate-changelog.sh — validate CHANGELOG.md format.
# Checks that the file exists and contains proper Keep a Changelog structure.
# Usage: scripts/validate-changelog.sh
set -euo pipefail

CHANGELOG="${1:-CHANGELOG.md}"
errors=0

if [[ ! -f "$CHANGELOG" ]]; then
	echo "ERROR: $CHANGELOG not found" >&2
	exit 1
fi

# Check for # Changelog heading
if ! head -1 "$CHANGELOG" | grep -q '^# Changelog'; then
	echo "ERROR: Missing '# Changelog' heading on line 1" >&2
	((errors++))
fi

# Check that every version entry has metadata (why, model, tags)
awk -v errors=0 '
/^## \[.*\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$/ {
	if (in_block && (!has_why || !has_model || !has_tags)) {
		print "ERROR: Version " prev_version " missing metadata (why/model/tags)" > "/dev/stderr"
		errors++
	}
	prev_version = $0
	in_block = 1
	has_why = 0
	has_model = 0
	has_tags = 0
	next
}
in_block && /^- \*\*why:\*\*/ { has_why = 1 }
in_block && /^- \*\*model:\*\*/ { has_model = 1 }
in_block && /^- \*\*tags:\*\*/ { has_tags = 1 }
/^## / && $0 !~ /^## \[/ {
	if (in_block && (!has_why || !has_model || !has_tags)) {
		print "ERROR: Section " $0 " is not a version entry format" > "/dev/stderr"
	}
	# Reset for non-version sub-headings (e.g. ### Added)
}
END {
	if (in_block && (!has_why || !has_model || !has_tags)) {
		print "ERROR: Version " prev_version " missing metadata (why/model/tags)" > "/dev/stderr"
		errors++
	}
	exit errors
}
' "$CHANGELOG" || ((errors++))

if ((errors > 0)); then
	echo "FAILED: $errors validation error(s)" >&2
	exit 1
fi

echo "OK: $CHANGELOG is valid"
