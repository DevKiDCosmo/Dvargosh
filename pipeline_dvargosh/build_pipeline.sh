#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[dvargosh] Starting CI/CD Automation Pipeline..."

echo "[1/7] Generating Module Embedded Headers and Companion Manifests in build/..."
python3 "${SCRIPT_DIR}/meta_header_tool.py" --all --out-dir "${ROOT_DIR}/build/modules" --headers-dir "${ROOT_DIR}/build/generated/headers"

echo "[2/7] Staging development modules into build/..."
mkdir -p "${ROOT_DIR}/build/development_modules"
if [ -d "${ROOT_DIR}/development_modules" ]; then
    cp -R "${ROOT_DIR}/development_modules/"* "${ROOT_DIR}/build/development_modules/"
fi

echo "[3/7] Running Pipeline Generator (Attributes, module.def, Proxies, Lint, Schema)..."
python3 "${SCRIPT_DIR}/generator.py"

echo "[4/7] Configuring & Building with CMake..."
cmake -B "${ROOT_DIR}/build" -S "${ROOT_DIR}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${ROOT_DIR}/build" --parallel

echo "[5/7] Synchronizing modules & Cryptographically Signing..."
mkdir -p "${ROOT_DIR}/build/modules"
# Copy all development module libraries into build/modules/ for unified loading
if [ -d "${ROOT_DIR}/build/development_modules" ]; then
    find "${ROOT_DIR}/build/development_modules" -type f \( -name "*.dylib" -o -name "*.so" \) -exec cp -f {} "${ROOT_DIR}/build/modules/" \;
fi
# Copy all .def manifests into build/modules/
find "${ROOT_DIR}/modules" "${ROOT_DIR}/development_modules" -type f -name "*.def" -exec cp -f {} "${ROOT_DIR}/build/modules/" \; 2>/dev/null || true

# Ensure source directories remain 100% pristine and free of generated files
find "${ROOT_DIR}/modules" "${ROOT_DIR}/development_modules" -type f \( -name "_module_header.*" -o -name "*.meta.json" -o -name "_generated_*" -o -name "*Modules.cmake" \) -delete 2>/dev/null || true

SECRET_KEY="dvargosh_master_signing_key_2026"
python3 "${ROOT_DIR}/tools/dvargosh_tool.py" sign "${ROOT_DIR}/build" "${SECRET_KEY}"

echo "[6/7] Running CTest & Verification Harness..."
ctest --test-dir "${ROOT_DIR}/build" --output-on-failure

echo "[7/7] Running Standalone App Loader Test, Generated Pipeline App, & Telecom Test..."
"${ROOT_DIR}/build/bin/dvargosh_app_loader_test"
if [ -f "${ROOT_DIR}/build/bin/dvargosh_pipeline_app" ]; then
    "${ROOT_DIR}/build/bin/dvargosh_pipeline_app"
fi
if [ -f "${ROOT_DIR}/build/bin/dvargosh_telecom_test" ]; then
    "${ROOT_DIR}/build/bin/dvargosh_telecom_test"
fi

echo "[dvargosh] Pipeline verification complete: All tests passed."
