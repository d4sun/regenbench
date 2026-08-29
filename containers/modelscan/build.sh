#!/bin/sh
set -e

IMAGE=regenbench/modelscan
VERSION=0.4.0
DIR="$(cd "$(dirname "$0")" && pwd)"

docker build -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" "$DIR"
echo "Built ${IMAGE}:${VERSION}"