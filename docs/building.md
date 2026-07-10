# Building OrchardSeal

## Requirements

- CMake 3.18+
- C99 and C++17 compilers
- OpenSSL 3.x development package
- Git for revision-aware version strings when building from a repository checkout

OrchardSeal builds vendored zlib and minizip internally. Do not install separate copies unless you intentionally change the build configuration.

## Linux

```bash
sudo apt-get update
sudo apt-get install -y cmake g++ pkg-config libssl-dev

cmake -S . -B build/release \
  -DCMAKE_BUILD_TYPE=Release \
  -DORCHARDSEAL_BUILD_TESTS=ON \
  -DORCHARDSEAL_WARNINGS_AS_ERRORS=ON
cmake --build build/release --parallel
ctest --test-dir build/release --output-on-failure
```

## macOS

```bash
brew install cmake openssl@3

cmake -S . -B build/release \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
  -DORCHARDSEAL_BUILD_TESTS=ON
cmake --build build/release --parallel
ctest --test-dir build/release --output-on-failure
```

## Windows

Install Visual Studio 2022, CMake, and OpenSSL through vcpkg:

```powershell
vcpkg install openssl:x64-windows

cmake -S . -B build -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DORCHARDSEAL_BUILD_TESTS=ON
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

## CMake options

| Option | Default | Purpose |
| --- | --- | --- |
| `ORCHARDSEAL_BUILD_TESTS` | `ON` | Register CLI, unit, SealCheck, parser-safety, and archive-safety tests. |
| `ORCHARDSEAL_WARNINGS_AS_ERRORS` | `OFF` | Promote warnings in OrchardSeal core and CLI code to errors. Vendored code is excluded. |
| `CMAKE_BUILD_TYPE` | Generator-specific | Select `Debug`, `Release`, `RelWithDebInfo`, or `MinSizeRel` for single-config generators. |
| `OPENSSL_ROOT_DIR` | Auto-detected | Point CMake at a non-default OpenSSL installation. |

Project C++ targets require standard C++17 with compiler extensions disabled.

## Presets

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug

cmake --preset release
cmake --build --preset release
ctest --preset release
```

The provided presets use Unix Makefiles. Visual Studio users should use the explicit Windows commands above or add a local user preset.

## Convenience scripts

```bash
scripts/build.sh Release
scripts/test.sh Release
make build
make test
```

Install into the selected CMake prefix:

```bash
cmake --install build/release
```

The install step includes the `orchardseal` executable plus the README, license, and third-party notices.

## Sanitizer build

OrchardSeal does not force a sanitizer toolchain, but standard CMake flags can be used on compatible Clang/GCC systems:

```bash
cmake -S . -B build/asan \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DORCHARDSEAL_BUILD_TESTS=ON \
  -DORCHARDSEAL_WARNINGS_AS_ERRORS=ON
cmake --build build/asan --parallel
ctest --test-dir build/asan --output-on-failure
```

## Troubleshooting

- **OpenSSL not found:** set `OPENSSL_ROOT_DIR` or the vcpkg toolchain file.
- **JSON output mixed with diagnostics:** do not enable `--debug` when consuming standard output as a machine stream; `--audit-report` is the safest integration path.
- **IPA audit cannot create temporary files:** pass an existing writable directory with `--temp_folder`.
- **Signing assets fail validation:** run `--audit` with the same `-k`, `-c`, `-m`, `-p`, and `-e` arguments to receive normalized findings before signing.
