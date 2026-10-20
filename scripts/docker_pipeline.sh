#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[dvargosh] Starting Containerized CI/CD Docker Pipeline..."

# 1. Build universal Docker image
echo "[dvargosh] Building Docker image (dvargosh:latest)..."
docker build -t dvargosh:latest "${ROOT_DIR}"

# 2. Run containerized verification demonstration
echo "[dvargosh] Executing automated verification demo inside container..."
docker run --rm dvargosh:latest /app/bin/dvargosh --modules /app/modules

# 3. Run pipeline demo app if present
echo "[dvargosh] Executing pipeline demo app inside container..."
if docker run --rm dvargosh:latest test -f /app/bin/dvargosh_pipeline_app; then
    docker run --rm dvargosh:latest /app/bin/dvargosh_pipeline_app
fi

echo "[dvargosh] Containerized verification pipeline succeeded (100% PASS)."
