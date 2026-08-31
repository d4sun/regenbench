#!/bin/bash
set -e
docker build -t regenbench/picklescan:patched "$(dirname "$0")"
echo "Built regenbench/picklescan:patched"
