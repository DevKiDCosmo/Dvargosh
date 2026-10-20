#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=========================================================="
echo "          DVARGOSH CI/CD AUTOMATION PIPELINE              "
echo "=========================================================="

echo "[1/5] Running Pipeline Generator (CMake & Lint Introspection)..."
python3 "${SCRIPT_DIR}/generator.py"

echo "[2/5] Configuring & Building with CMake..."
cmake -B "${ROOT_DIR}/build" -S "${ROOT_DIR}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${ROOT_DIR}/build" --parallel

echo "[3/5] Cryptographically Signing All Built Modules..."
SECRET_KEY="dvargosh_master_signing_key_2026"
python3 "${ROOT_DIR}/tools/dvargosh_tool.py" sign "${ROOT_DIR}/build" "${SECRET_KEY}"

echo "[4/5] Running CTest & Verification Harness..."
ctest --test-dir "${ROOT_DIR}/build" --output-on-failure --verbose

echo "[5/5] Running Standalone App Loader Test..."
"${ROOT_DIR}/build/bin/dvargosh_app_loader_test"

echo "=========================================================="
echo "          PIPELINE VERIFICATION COMPLETE: ALL PASS        "
echo "=========================================================="
