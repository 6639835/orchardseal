# OrchardSeal

**OrchardSeal** is a cross-platform command-line toolkit for inspecting, validating, and signing iOS Mach-O binaries, application bundles, and IPA archives. It runs on Linux, macOS, and Windows and uses OpenSSL for certificate, CMS, and provisioning-profile operations.

Its flagship capability is **SealCheck**, a read-only preflight engine designed for local workflows and CI. SealCheck explains whether an artifact is structurally ready for signing, identifies blocking conditions, and can emit a stable JSON report before any mutation takes place.

## Highlights

- **Read-only preflight audits** for Mach-O files, `.app` bundles, directories, and `.ipa` archives.
- **Human-readable and JSON reports**, with optional report-file output and strict CI exit behavior.
- **Mach-O inspection and signing** across thin and fat binaries.
- **Bundle-aware signing** for apps, extensions, frameworks, test bundles, and nested binaries.
- **Provisioning checks** for expiration, team identifiers, application identifiers, and wildcard matching.
- **Signing-asset validation** for certificates, private keys or PKCS#12 files, passwords, profiles, and entitlements.
- **Bundle customization** including identifier, display name, version, minimum OS version, icons, and document-sharing keys.
- **Dylib injection and removal** with configurable bundle scope.
- **Defensive archive extraction** that rejects traversal paths and cleans failed temporary workspaces.

## SealCheck preflight audits

Run a non-destructive audit:

```bash
orchardseal --audit MyApp.ipa
```

Emit JSON to standard output:

```bash
orchardseal --audit --audit-format json MyApp.ipa
```

Save the complete JSON report while keeping readable output in the terminal:

```bash
orchardseal --audit \
  --audit-report reports/MyApp.audit.json \
  MyApp.ipa
```

Make warnings fail a CI job:

```bash
orchardseal --audit --strict-audit MyApp.ipa
```

Validate a proposed signing set without signing the input:

```bash
orchardseal --audit \
  -k distribution.p12 \
  -p "$P12_PASSWORD" \
  -m AppStore.mobileprovision \
  MyApp.ipa
```

SealCheck inspects:

- archive path safety and IPA `Payload/*.app` layout;
- `Info.plist` readability and required bundle metadata;
- duplicate bundle identifiers and declared executable paths;
- Mach-O architecture slices, file types, encryption commands, and code-signature slots;
- arm64-family coverage for main executables;
- embedded and supplied provisioning profiles, including expiration and bundle-ID compatibility;
- certificate/private-key/profile compatibility when signing assets are supplied.

Audit mode maps binaries read-only. IPA contents are extracted to an isolated temporary directory and removed after the report is produced. The input artifact is not modified.

### Audit exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Audit completed with no errors. Warnings are allowed unless strict mode is enabled. |
| `1` | Operational failure, such as an unreadable input, failed extraction, or report-write failure. |
| `2` | Invalid or incomplete command-line option. |
| `3` | Audit findings block the workflow: errors were found, or warnings were found under `--strict-audit`. |

`ready_for_signing` in the JSON report means that SealCheck found no error-severity issue. Warnings remain visible so policy decisions can be made by the caller.

### JSON report contract

Reports use schema version `1.0` and include product metadata, summary counts, signing-asset status, profiles, bundles, binaries, architecture slices, and normalized issues.

```json
{
  "schema_version": "1.0",
  "product": "OrchardSeal",
  "engine": "SealCheck",
  "input_type": "ipa-archive",
  "ready_for_signing": true,
  "summary": {
    "bundle_count": 2,
    "binary_count": 5,
    "warning_count": 0,
    "error_count": 0
  },
  "issues": []
}
```

`--audit-format` controls standard output. `--audit-report PATH` always writes the full JSON representation and implies `--audit`.

## Signing usage

```text
orchardseal [options] [-k private-key-or-p12] [-m profile.mobileprovision] [-o output.ipa] file|folder
```

Inspect a Mach-O file without modifying it:

```bash
orchardseal MyAppBinary
```

Ad-hoc sign a single Mach-O file in place:

```bash
orchardseal --adhoc MyAppBinary
```

Sign an IPA:

```bash
orchardseal \
  -k distribution.p12 \
  -p "$P12_PASSWORD" \
  -m AppStore.mobileprovision \
  -o MyApp-signed.ipa \
  MyApp.ipa
```

Change bundle metadata while signing:

```bash
orchardseal \
  -k distribution.p12 \
  -p "$P12_PASSWORD" \
  -m AppStore.mobileprovision \
  -b com.example.new-identifier \
  -n "Example App" \
  -r 42 \
  -o MyApp-signed.ipa \
  MyApp.ipa
```

Supply multiple provisioning profiles for nested bundles by repeating `-m`. Run `orchardseal --help` for every signing, mutation, diagnostic, and audit option.

> Signing a Mach-O file or an unpacked bundle without an output archive modifies that input in place. Run SealCheck first and work from a backup or reproducible build artifact.

## Build

### Requirements

- CMake 3.18 or newer
- A C99 compiler and a C++17 compiler
- OpenSSL 3.x development headers and libraries
- A CMake-supported build tool

Linux dependencies:

```bash
sudo apt-get update
sudo apt-get install -y cmake g++ pkg-config libssl-dev
```

macOS dependencies:

```bash
brew install cmake openssl@3
```

Configure, build, and test:

```bash
cmake -S . -B build/release \
  -DCMAKE_BUILD_TYPE=Release \
  -DORCHARDSEAL_WARNINGS_AS_ERRORS=ON
cmake --build build/release --parallel
ctest --test-dir build/release --output-on-failure
```

For Homebrew OpenSSL:

```bash
cmake -S . -B build/release \
  -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

CMake presets and convenience targets are also available:

```bash
cmake --preset release
cmake --build --preset release
ctest --preset release

make build
make test
```

See [docs/building.md](docs/building.md) for Windows and platform-specific instructions.

## Test coverage

The public CTest suite verifies:

- version and help entry points;
- Mach-O, app-bundle, and IPA SealCheck flows;
- text and JSON report behavior;
- report-file creation;
- strict warning exit code `3`;
- rejection and cleanup of a malicious ZIP traversal fixture;
- rejection of malformed Mach-O load-command tables without unsafe reads;
- Base64 binary/vector behavior and little-/big-endian dylib-command rebuilding.

Real signing integration tests require private certificates, profiles, and authorized application fixtures, so those assets are intentionally excluded from the repository.

## Project layout

```text
.
├── CMakeLists.txt
├── cmake/                         Compiler and build policy
├── docs/                          Architecture, build, and release guides
├── include/orchardseal/           Generated version metadata
├── scripts/                       Build, test, and package helpers
├── src/
│   ├── cli/                       Argument parsing and application orchestration
│   ├── common/                    Filesystem, archive, JSON, hashing, and logging utilities
│   ├── core/                      SealCheck, Mach-O, signing, bundle, and certificate logic
│   └── platform/windows/          Windows compatibility shims
├── tests/                         CTest scripts and synthetic fixtures
```

The architecture and ownership rules are documented in [docs/architecture.md](docs/architecture.md).

## Security and responsible use

Use OrchardSeal only with applications and signing assets you are authorized to inspect or modify. Never commit private keys, PKCS#12 files, provisioning profiles, customer applications, or signed IPA artifacts. See [SECURITY.md](SECURITY.md) for reporting and handling guidance.

## License

OrchardSeal is distributed under the MIT License. See [LICENSE](LICENSE).
