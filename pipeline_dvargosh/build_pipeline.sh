#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[dvargosh] Starting CI/CD Automation Pipeline..."

echo "[1/6] Staging development modules..."
mkdir -p "${ROOT_DIR}/build/development_modules"
if [ -d "${ROOT_DIR}/development_modules" ]; then
    cp -R "${ROOT_DIR}/development_modules/"* "${ROOT_DIR}/build/development_modules/"
fi

echo "[2/6] Running Pipeline Generator (Attributes, module.def, Proxies, Lint, Schema)..."
python3 "${SCRIPT_DIR}/generator.py"

echo "[3/6] Configuring & Building with CMake..."
cmake -B "${ROOT_DIR}/build" -S "${ROOT_DIR}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${ROOT_DIR}/build" --parallel

echo "[4/6] Synchronizing modules & Cryptographically Signing..."
mkdir -p "${ROOT_DIR}/build/modules"
# Copy all development module libraries into build/modules/ for unified loading
if [ -d "${ROOT_DIR}/build/development_modules" ]; then
    find "${ROOT_DIR}/build/development_modules" -type f \( -name "*.dylib" -o -name "*.so" \) -exec cp -f {} "${ROOT_DIR}/build/modules/" \;
fi
# Copy all .def manifests into build/modules/
find "${ROOT_DIR}/modules" "${ROOT_DIR}/development_modules" -type f -name "*.def" -exec cp -f {} "${ROOT_DIR}/build/modules/" \; 2>/dev/null || true

SECRET_KEY="dvargosh_master_signing_key_2026"
python3 "${ROOT_DIR}/tools/dvargosh_tool.py" sign "${ROOT_DIR}/build" "${SECRET_KEY}"

echo "[5/6] Running CTest & Verification Harness..."
ctest --test-dir "${ROOT_DIR}/build" --output-on-failure

echo "[6/6] Running Standalone App Loader Test & Generated Pipeline App..."
"${ROOT_DIR}/build/bin/dvargosh_app_loader_test"
if [ -f "${ROOT_DIR}/build/bin/dvargosh_pipeline_app" ]; then
    "${ROOT_DIR}/build/bin/dvargosh_pipeline_app"
fi

echo "[dvargosh] Pipeline verification complete: All tests passed."
