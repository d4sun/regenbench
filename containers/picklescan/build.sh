#!/bin/sh
set -e

# Build the PickleScan scanner container image.
#
# Usage:
#   ./build.sh                              # default pin (v1.0.5)
#   ./build.sh 1.0.4 bf26452ae2e3204429762c2bb1aa9eacd40436bb   # historical release
#
# The first arg is the scanner release tag (also used as the container tag),
# the second is the full upstream git commit SHA to check out.

IMAGE=regenbench/picklescan
VERSION="${1:-0.3.0}"
COMMIT="${2:-f15d54da3dec9aa28a87ede82f87882bb80f1023}"
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