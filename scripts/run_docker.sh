#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Building Universal Docker Container ==="
docker build -t dvargosh:latest "${ROOT_DIR}"

echo "=== Running Containerized Verification Suite ==="
docker run --rm dvargosh:latest
