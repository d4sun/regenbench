#!/bin/sh
set -e

IMAGE=regenbench/modeltracer
VERSION=0.6.0
DIR="$(cd "$(dirname "$0")" && pwd)"

docker build -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" "$DIR"
echo "Built ${IMAGE}:${VERSION}"