#!/bin/sh
set -e

# Build the Fickling scanner container image.
#
# Usage:
#   ./build.sh                              # default pin (v0.1.12)
#   ./build.sh 0.1.11 62028fbb8e60742469a77ef07c9aabd33e3cb568   # historical release
#
# The first arg is the scanner release tag (also used as the container tag),
# the second is the full upstream git commit SHA to check out.

IMAGE=regenbench/fickling
VERSION="${1:-0.5.0}"
COMMIT="${2:-c3c695cdcce451c04dfe892802675161614287a2}"
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