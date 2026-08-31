#!/bin/bash
set -e
docker build -t regenbench/modelscan:patched "$(dirname "$0")"
echo "Built regenbench/modelscan:patched"
