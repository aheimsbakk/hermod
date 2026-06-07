#!/usr/bin/env bash
# scripts/build-release.sh — cross-compile hermod for a single OS/arch pair.
# Output: dist/hermod-<os>-<arch> (or .exe for windows).
#
# Usage: scripts/build-release.sh <os> <arch> [output_dir]
#   <os>    Target OS: linux, windows, darwin
#   <arch>  Target architecture: amd64, arm64
#   [output_dir]  Output directory (default: dist/)
#
# Examples:
#   scripts/build-release.sh linux amd64
#   scripts/build-release.sh windows arm64 ./build-output
set -euo pipefail

OS="${1:?Usage: $0 <os> <arch> [output_dir]}"
ARCH="${2:?Usage: $0 <os> <arch> [output_dir]}"
OUTPUT_DIR="${3:-dist}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$REPO_ROOT/VERSION" | tr -d '[:space:]')"

BINARY="hermod-${OS}-${ARCH}"
if [ "$OS" = "windows" ]; then
	BINARY="${BINARY}.exe"
fi

mkdir -p "$OUTPUT_DIR"

echo "Building ${BINARY} (${OS}/${ARCH}) ..."

GOOS="$OS" GOARCH="$ARCH" CGO_ENABLED=0 go build \
	-ldflags="-s -w -X github.com/hermod/hermod/internal/cli.appVersion=${VERSION}" \
	-o "$OUTPUT_DIR/${BINARY}" \
	"$REPO_ROOT/cmd/hermod/"

echo "  -> ${OUTPUT_DIR}/${BINARY}"
