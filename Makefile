.PHONY: configure build test audit-smoke clean install

BUILD_DIR ?= build/release
BUILD_TYPE ?= Release

configure:
	cmake -S . -B $(BUILD_DIR) \
		-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
		-DORCHARDSEAL_BUILD_TESTS=ON

build: configure
	cmake --build $(BUILD_DIR) --parallel

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

audit-smoke: build
	$(BUILD_DIR)/orchardseal --audit --audit-format json tests/fixtures/macho/arm64-executable

install: build
	cmake --install $(BUILD_DIR)

clean:
	rm -rf build bin dist install
