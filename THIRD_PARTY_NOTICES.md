# Third-party notices

OrchardSeal is distributed under the MIT License in [LICENSE](LICENSE). The repository also uses the following third-party components.

## zlib

Location: `vendor/zlib/`

zlib is distributed under the zlib license. The applicable notices are retained in the upstream source files.

## minizip

Location: `vendor/minizip/`

minizip originates from the zlib contrib tree and carries zlib-compatible notices retained in its source files.

## OpenSSL

OpenSSL is not vendored. CMake resolves it as a system dependency with `find_package(OpenSSL REQUIRED)`. Distributors must comply with the license terms of the OpenSSL version they build and ship.

## Apple platform formats and identifiers

The source contains constants and structure definitions needed to process Mach-O binaries, code-signature blobs, property lists, and provisioning data. Apple, iOS, macOS, Xcode, and related marks belong to their respective owners. OrchardSeal is not affiliated with or endorsed by Apple Inc.
