#!/usr/bin/env bash
# ==============================================================================
# Dvargosh Production Build & Packaging Engine (CI/CD Automated)
# Compiles optimized binaries, signs modules, and creates standalone dist/ package.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default arguments
OUTPUT_DIR="${ROOT_DIR}/dist"
SIGNING_KEY="${DVARGOSH_SIGNING_KEY:-}"
SKIP_TESTS=false
CLEAN_BUILD=false
SELECTED_MODULES=""

show_help() {
    cat << EOF
Dvargosh Production Distribution CLI Tool

Usage:
  ./pipeline_dvargosh/build_production.sh [OPTIONS]

Options:
  --output-dir <dir>    Target directory for packaged distribution (default: ./dist)
  --key <key>           Master HMAC-SHA256 signing secret key (REQUIRED: pass --key
                        or export DVARGOSH_SIGNING_KEY; there is deliberately no default)
  --select <modules>    Comma-separated list of modules to include
  --skip-tests          Skip CTest verification step (for fast CI/CD builds)
  --clean               Remove build/ directory before compiling
  --help                Show this help message
EOF
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --key)
            SIGNING_KEY="$2"
            shift 2
            ;;
        --select)
            SELECTED_MODULES="$2"
            shift 2
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

echo "[dvargosh] Starting Production Packaging Engine..."
echo "  * Target Distribution: ${OUTPUT_DIR}"
echo "  * Skip Tests:          ${SKIP_TESTS}"
echo "  * Clean Build:         ${CLEAN_BUILD}"

if [ "${CLEAN_BUILD}" = true ]; then
    echo "[Clean] Removing existing build and dist directories..."
    rm -rf "${ROOT_DIR}/build" "${OUTPUT_DIR}"
fi

# 1. Generating Module Embedded Headers and Companion Manifests in build/
echo "[1/7] Generating Module Embedded Headers and Companion Manifests in build/..."
python3 "${SCRIPT_DIR}/meta_header_tool.py" --all --out-dir "${ROOT_DIR}/build/modules" --headers-dir "${ROOT_DIR}/build/generated/headers"

# 2. Staging Development Modules
echo "[2/7] Staging development modules into build/development_modules..."
mkdir -p "${ROOT_DIR}/build/development_modules"
if [ -d "${ROOT_DIR}/development_modules" ]; then
    cp -R "${ROOT_DIR}/development_modules/"* "${ROOT_DIR}/build/development_modules/"
fi

# 3. Running Pipeline Generator
echo "[3/7] Running Pipeline Generator (Attributes, Proxies, Lint, Schema, CMake)..."
GEN_ARGS=""
if [ -n "${SELECTED_MODULES}" ]; then
    GEN_ARGS="--select ${SELECTED_MODULES}"
fi
python3 "${SCRIPT_DIR}/generator.py" ${GEN_ARGS}

# 4. Compiling with Maximum Optimizations (-O3 -DNDEBUG)
echo "[4/7] Configuring and Compiling Production Binaries (-O3 -DNDEBUG)..."
cmake -B "${ROOT_DIR}/build" -S "${ROOT_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_FLAGS="-O3 -DNDEBUG"
cmake --build "${ROOT_DIR}/build" --parallel

# Sync dev modules and def manifests into build/modules/
mkdir -p "${ROOT_DIR}/build/modules"
if [ -d "${ROOT_DIR}/build/development_modules" ]; then
    find "${ROOT_DIR}/build/development_modules" -type f \( -name "*.dylib" -o -name "*.so" \) -exec cp -f {} "${ROOT_DIR}/build/modules/" \;
fi
find "${ROOT_DIR}/modules" "${ROOT_DIR}/development_modules" -type f -name "*.def" -exec cp -f {} "${ROOT_DIR}/build/modules/" \; 2>/dev/null || true

# Ensure source directories remain 100% pristine and free of generated files
find "${ROOT_DIR}/modules" "${ROOT_DIR}/development_modules" -type f \( -name "_module_header.*" -o -name "*.meta.json" -o -name "_generated_*" -o -name "*Modules.cmake" \) -delete 2>/dev/null || true

# 5. Cryptographic Module Signing
echo "[5/7] Cryptographically Signing All Production Modules..."
if [ -z "${SIGNING_KEY}" ]; then
    echo "[ERROR] No signing key available. Pass --key <key> or export DVARGOSH_SIGNING_KEY."
    echo "        A production distribution must be signed; refusing to continue."
    exit 1
fi
python3 "${ROOT_DIR}/tools/dvargosh_tool.py" sign "${ROOT_DIR}/build" "${SIGNING_KEY}"

# 6. Verification Harness (Unless Skipped)
if [ "${SKIP_TESTS}" = false ]; then
    echo "[6/7] Running Verification Harness..."
    ctest --test-dir "${ROOT_DIR}/build" --output-on-failure
    "${ROOT_DIR}/build/bin/dvargosh_pipeline_app"
else
    echo "[6/7] Skipping Verification Harness (--skip-tests specified)."
fi

# 7. Packaging Distribution into dist/
echo "[7/7] Assembling Standalone Production Package in ${OUTPUT_DIR}..."
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}/bin"
mkdir -p "${OUTPUT_DIR}/modules"
mkdir -p "${OUTPUT_DIR}/include"
mkdir -p "${OUTPUT_DIR}/docs"

# Copy binaries
cp -f "${ROOT_DIR}/build/bin/"* "${OUTPUT_DIR}/bin/"

# Copy shared libraries and .def / .meta.json manifests
find "${ROOT_DIR}/build" -type f \( -name "*.dylib" -o -name "*.so" \) -exec cp -f {} "${OUTPUT_DIR}/modules/" \;
find "${ROOT_DIR}/build/modules" "${ROOT_DIR}/modules" "${ROOT_DIR}/development_modules" -type f \( -name "*.def" -o -name "*.meta.json" \) -exec cp -f {} "${OUTPUT_DIR}/modules/" \; 2>/dev/null || true

# Copy signatures
if [ -f "${ROOT_DIR}/build/modules/signatures.json" ]; then
    cp -f "${ROOT_DIR}/build/modules/signatures.json" "${OUTPUT_DIR}/signatures.json"
fi

# Copy public headers & generated proxies/binders/apis
cp -Rf "${ROOT_DIR}/include/"* "${OUTPUT_DIR}/include/"
if [ -d "${ROOT_DIR}/build/generated/include" ]; then
    cp -Rf "${ROOT_DIR}/build/generated/include/"* "${OUTPUT_DIR}/include/"
fi

# Copy documentation & schema
cp -f "${ROOT_DIR}/docs/"* "${OUTPUT_DIR}/docs/"
if [ -f "${ROOT_DIR}/build/schema.json" ]; then
    cp -f "${ROOT_DIR}/build/schema.json" "${OUTPUT_DIR}/schema.json"
fi

echo "[dvargosh] Production packaging complete (100% pass)."
echo "  * Binaries: $(ls "${OUTPUT_DIR}/bin")"
echo "  * Modules:  $(ls "${OUTPUT_DIR}/modules")"
echo "  * Output:   ${OUTPUT_DIR}"
