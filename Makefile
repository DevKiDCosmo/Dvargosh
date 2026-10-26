.PHONY: all build test demo interactive clean docker-build docker-test docker-interactive generate-cmake sign-modules pipeline full-pipeline production setup new-module sanitize threadcheck hardened fuzz-smoke lint tidy secure

BUILD_DIR ?= build
MODULES_DIR ?= $(BUILD_DIR)/modules

all: build test

setup:
	python3 pipeline_dvargosh/setup.py

new-module:
	python3 pipeline_dvargosh/scaffold.py $(if $(NAME),--name $(NAME),) $(if $(DOMAIN),--domain $(DOMAIN),)

pipeline full-pipeline:
	./pipeline_dvargosh/build_pipeline.sh

production:
	./pipeline_dvargosh/build_production.sh

generate-cmake:
	python3 tools/dvargosh_tool.py generate-cmake

# Signing requires an out-of-band key: export DVARGOSH_SIGNING_KEY (never commit it).
sign-modules: build
	@if [ -z "$$DVARGOSH_SIGNING_KEY" ]; then \
		echo "[ERROR] DVARGOSH_SIGNING_KEY is not set. Refusing to sign with a default key."; \
		echo "        export DVARGOSH_SIGNING_KEY=<secret>  (or use a CI secret / keyfile)"; \
		exit 1; \
	fi
	python3 tools/dvargosh_tool.py sign $(MODULES_DIR) "$$DVARGOSH_SIGNING_KEY"

build:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) --parallel

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure --verbose

# --- Secure development presets (see CMakePresets.json) ---

sanitize:
	cmake --preset sanitize && cmake --build --preset sanitize --parallel
	ctest --preset sanitize

threadcheck:
	cmake --preset thread && cmake --build --preset thread --parallel
	ctest --preset thread

hardened:
	cmake --preset hardened-release && cmake --build --preset hardened-release --parallel
	ctest --preset hardened-release

fuzz-smoke:
	cmake --preset fuzz && cmake --build --preset fuzz --parallel
	ctest --preset fuzz -R "Smoke" --output-on-failure

tidy:
	@command -v clang-tidy >/dev/null 2>&1 || { echo "[ERROR] clang-tidy not found (xcode-select --install or brew install llvm)"; exit 1; }
	git diff --name-only --diff-filter=ACMR HEAD -- '*.cpp' '*.hpp' | grep -v '^build/' | while read f; do \
		clang-tidy -p $(BUILD_DIR) --config-file=.clang-tidy "$$f"; \
	done

lint:
	python3 pipeline_dvargosh/lint.py

# Full local secure gate: mirrors what CI enforces.
secure: sanitize lint
	@echo "[secure] sanitizer tests + lint passed."

demo: build
	./$(BUILD_DIR)/bin/dvargosh --modules $(MODULES_DIR)

interactive: build
	./$(BUILD_DIR)/bin/dvargosh --modules $(MODULES_DIR) --interactive

clean:
	rm -rf $(BUILD_DIR) dist
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.dSYM" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.dylib" -delete 2>/dev/null || true
	find . -type f -name "*.so" -delete 2>/dev/null || true
	find . -type f -name "_generated_registration.cpp" -delete 2>/dev/null || true

docker-build:
	docker build -t dvargosh:latest .

docker-test:
	docker run --rm dvargosh:latest

docker-interactive:
	docker run -it --rm dvargosh:latest /app/bin/dvargosh --modules /app/modules --interactive

docker-pipeline:
	./scripts/docker_pipeline.sh
