#!/usr/bin/env bash
set -euo pipefail

build_type="${1:-Release}"
build_dir="build/${build_type,,}"

cmake -S . -B "$build_dir" -DCMAKE_BUILD_TYPE="$build_type"
cmake --build "$build_dir" --parallel
