#!/usr/bin/env bash
set -euo pipefail

build_type="${1:-Release}"
case "$build_type" in
    Debug|debug|DEBUG) build_type="Debug"; build_dir="build/debug" ;;
    Release|release|RELEASE) build_type="Release"; build_dir="build/release" ;;
    RelWithDebInfo|relwithdebinfo|RELWITHDEBINFO) build_type="RelWithDebInfo"; build_dir="build/relwithdebinfo" ;;
    MinSizeRel|minsizerel|MINSIZEREL) build_type="MinSizeRel"; build_dir="build/minsizerel" ;;
    *)
        echo "Unsupported build type: $build_type" >&2
        exit 2
        ;;
esac

cmake -S . -B "$build_dir" -DCMAKE_BUILD_TYPE="$build_type"
cmake --build "$build_dir" --parallel
