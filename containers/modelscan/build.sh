#!/bin/sh
set -e

# Build the ModelScan scanner container image.
#
# Usage:
#   ./build.sh                              # default pin (v0.8.8)
#   ./build.sh 0.8.7 abc4b1510315ba1ba162e3ae002e5d394db32200   # historical release
#
# The first arg is the scanner release tag (also used as the container tag),
# the second is the full upstream git commit SHA to check out.

IMAGE=regenbench/modelscan
VERSION="${1:-0.4.0}"
COMMIT="${2:-61fcec9c2a37c24c1fb12d84ede30fe248a364bd}"
DIR="$(cd "$(dirname "$0")" && pwd)"

TAGS=(-t "${IMAGE}:${VERSION}")
# Default pin also refreshes :latest; historical builds keep their own tag.
if [ "$#" -eq 0 ]; then
  TAGS+=(-t "${IMAGE}:latest")
fi

docker build \
  --build-arg SCANNER_COMMIT="${COMMIT}" \
  "${TAGS[@]}" "$DIR"
echo "Built ${IMAGE}:${VERSION} (scanner commit ${COMMIT})"