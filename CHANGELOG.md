# Changelog

All notable OrchardSeal changes are documented here.

## 1.0.0 - 2026-07-10

### Product launch

- Introduced the OrchardSeal product identity, `orchardseal` executable, CMake targets, generated headers, cache/debug paths, scripts, CI names, package metadata, and documentation.
- Added **SealCheck**, a read-only preflight engine for Mach-O files, app bundles, directories, and IPA archives.

### SealCheck

- Added human-readable and schema-versioned JSON reports.
- Added `--audit`, `--audit-format`, `--audit-report`, and `--strict-audit`.
- Added stable audit exit codes for local automation and CI.
- Added checks for IPA layout, archive path safety, plist readability, required bundle metadata, duplicate bundle identifiers, declared executables, Mach-O file types, arm64 coverage, encryption, code-signature slots, provisioning expiration, application-identifier matching, and optional signing-asset compatibility.
- Added deterministic temporary extraction and cleanup for archive audits.

### Architecture and maintainability

- Separated CLI parsing, application orchestration, audit scanning, report serialization, signing behavior, common utilities, Windows compatibility code, and vendored dependencies.
- Renamed core files and types around their responsibilities, including `MachOFile`, `MachOSlice`, `AppBundle`, `SigningAsset`, `CodeSignature`, `FileSystem`, `ZipArchive`, `Hash`, `Logger`, and `Stopwatch`.
- Encapsulated bundle configuration, signing credentials, Mach-O parser state, and inspection results behind named APIs with explicit defaults.
- Reworked Mach-O mappings and architecture slices to use deterministic ownership, read-only inspection mappings, and rollback-safe replacement.
- Replaced manual buffers in Base64 conversion, Windows text conversion, and dylib-command rebuilding with RAII containers and stable descriptive APIs.
- Made the Windows text converter part of the core target where it is consumed, so CLI and standalone test targets share the same linkage model.
- Enforced C++17 without compiler extensions and applied warnings-as-errors to project core, CLI, and unit-test targets.

### Security and correctness

- Hardened ZIP extraction against absolute paths, drive-qualified names, alternate separators, traversal components, control characters, duplicate entries, and ambiguous path endings.
- Changed unsafe archive entries from skip behavior to fail-closed extraction and guaranteed partial-workspace cleanup.
- Removed permission-changing fallback behavior from read-only file mapping and prevented Windows mapping from creating missing files.
- Added strict bounds validation for thin/fat Mach-O slices, load-command tables, sections, strings, signature regions, and embedded signature index entries.
- Fixed mapped-file and architecture-slice lifecycle leaks in inspection paths.
- Fixed a fat-binary cross-slice state leak by making executable-segment limits per-slice.
- Fixed big-endian load-command size handling and made dylib removal a bounded, reparsable rebuild.
- Fixed alignment calculations that added a full block to already aligned values.
- Normalized CLI operational failures to portable exit code `1`.

### Tests and delivery

- Added seven credential-free CTest checks covering version/help output, Base64 behavior, little- and big-endian dylib removal, Mach-O/app/IPA audits, JSON report files, strict warning behavior, malformed Mach-O rejection, and malicious ZIP traversal cleanup.
- Validated warnings-as-errors builds with GCC and Clang, plus Debug and ASan/UBSan configurations.
- Added Linux, macOS, and Windows CI definitions, CMake presets, Docker build validation, install rules, source packaging with SHA-256 output, helper scripts, contribution guidance, security guidance, and release documentation.
