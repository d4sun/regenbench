#!/bin/sh
set -e

IMAGE=regenbench/gguf
VERSION=0.1.0
DIR="$(cd "$(dirname "$0")" && pwd)"

docker build -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" "$DIR"
echo "Built ${IMAGE}:${VERSION}"