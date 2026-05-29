#!/usr/bin/env bash
# scripts/check-coverage.sh — run per-package coverage and fail if any
# required package falls below the 80% threshold.
#
# Usage: scripts/check-coverage.sh
#   Exits 0 if all required packages meet the threshold.
#   Exits 1 if any required package is below the threshold or tests fail.
#
# Required packages (must reach ≥80% statement coverage):
#   - ./internal/cli/...
#   - ./internal/network/...
set -euo pipefail

THRESHOLD=80
TMPDIR_ROOT="$(mktemp -d /tmp/hermod-coverage-XXXXXX)"
trap 'rm -rf "$TMPDIR_ROOT"' EXIT

FAILED=0

check_package() {
	local label="$1"
	local pattern="$2"
	local covfile="$TMPDIR_ROOT/$(echo "$label" | tr '/' '_').out"

	echo "Testing $pattern ..."
	go test -count=1 -timeout=300s \
		-coverprofile="$covfile" \
		-covermode=atomic \
		"$pattern"

	local pct
	pct="$(go tool cover -func="$covfile" |
		awk '/^total:/ { gsub(/%/, "", $3); print $3 }')"

	if [[ -z "$pct" ]]; then
		echo "ERROR: could not parse coverage for $pattern" >&2
		return 1
	fi

	local passes
	passes="$(awk -v pct="$pct" -v thr="$THRESHOLD" \
		'BEGIN { print (pct + 0 >= thr + 0) ? "yes" : "no" }')"

	if [[ "$passes" == "yes" ]]; then
		printf "PASS  %-45s %s%% >= %s%%\n" "$pattern" "$pct" "$THRESHOLD"
	else
		printf "FAIL  %-45s %s%% < %s%%\n" "$pattern" "$pct" "$THRESHOLD" >&2
		return 1
	fi
}

echo "Coverage threshold: ${THRESHOLD}%"
echo ""

check_package "cli" "./internal/cli/..." || FAILED=1
check_package "network" "./internal/network/..." || FAILED=1

echo ""
if [[ "$FAILED" -ne 0 ]]; then
	echo "Coverage check FAILED: one or more packages are below ${THRESHOLD}%." >&2
	exit 1
fi

echo "All packages meet the ${THRESHOLD}% coverage threshold."
