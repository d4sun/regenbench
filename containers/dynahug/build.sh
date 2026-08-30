#!/bin/sh
set -e

IMAGE=regenbench/dynahug
VERSION=0.7.0
DIR="$(cd "$(dirname "$0")" && pwd)"

docker build -t "${IMAGE}:${VERSION}" -t "${IMAGE}:latest" "$DIR"
echo "Built ${IMAGE}:${VERSION}"