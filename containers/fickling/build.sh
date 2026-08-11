#!/bin/sh
set -e

IMAGE=regenbench/fickling
VERSION=0.5.0
DIR="$(cd "$(dirname "$0")" && pwd)"

podman build -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" "$DIR"
echo "Built ${IMAGE}:${VERSION}"