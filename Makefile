.PHONY: all build test demo interactive clean docker-build docker-test docker-interactive generate-cmake sign-modules pipeline full-pipeline production setup new-module

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
