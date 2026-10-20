.PHONY: all build test demo interactive clean docker-build docker-test docker-interactive generate-cmake sign-modules

BUILD_DIR ?= build
MODULES_DIR ?= $(BUILD_DIR)/modules

all: build test

generate-cmake:
	python3 tools/dvargosh_tool.py generate-cmake

sign-modules: build
	python3 tools/dvargosh_tool.py sign $(MODULES_DIR) dvargosh_master_signing_key_2026

build:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) --parallel

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure --verbose

demo: build
	./$(BUILD_DIR)/bin/dvargosh --modules $(MODULES_DIR)

interactive: build
	./$(BUILD_DIR)/bin/dvargosh --modules $(MODULES_DIR) --interactive

clean:
	rm -rf $(BUILD_DIR)

docker-build:
	docker build -t dvargosh:latest .

docker-test:
	docker run --rm dvargosh:latest

docker-interactive:
	docker run -it --rm dvargosh:latest /app/bin/dvargosh --modules /app/modules --interactive
