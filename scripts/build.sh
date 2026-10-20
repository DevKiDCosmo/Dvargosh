#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Building Dvargosh (Release) ==="
cmake -B "${ROOT_DIR}/build" -S "${ROOT_DIR}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${ROOT_DIR}/build" --parallel

echo "=== Running Tests ==="
ctest --test-dir "${ROOT_DIR}/build" --output-on-failure --verbose

echo "=== Running Automated Verification Demo ==="
"${ROOT_DIR}/build/bin/dvargosh" --modules "${ROOT_DIR}/build/modules"

echo "=== Build and Verification Complete! ==="
