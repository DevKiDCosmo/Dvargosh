.PHONY: all build test demo interactive clean docker-build docker-test docker-interactive

BUILD_DIR ?= build
MODULES_DIR ?= $(BUILD_DIR)/modules

all: build test

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
