#!/usr/bin/env bash
set -euo pipefail

build_type="${1:-Release}"
build_dir="build/${build_type,,}"

cmake -S . -B "$build_dir" -DCMAKE_BUILD_TYPE="$build_type" -DORCHARDSEAL_BUILD_TESTS=ON
cmake --build "$build_dir" --parallel
ctest --test-dir "$build_dir" --output-on-failure
