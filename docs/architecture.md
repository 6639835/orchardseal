# OrchardSeal architecture

## Design goals

OrchardSeal separates command handling, domain behavior, reusable infrastructure, and pinned third-party dependencies so signing logic can evolve without turning the CLI into a second implementation of the core.

The main rules are:

- command-line parsing belongs in `src/cli`;
- Mach-O, bundle, certificate, provisioning, and audit behavior belongs in `src/core`;
- generic filesystem, archive, JSON, hashing, timing, and logging code belongs in `src/common`;
- platform compatibility code remains isolated under `src/platform`;
- third-party source is fetched from the pinned upstream zlib release and is not reformatted with project code;
- inspection paths are read-only and mutation paths are explicit;
- resource-owning code uses deterministic cleanup and RAII where possible.

## Layers

### CLI: `src/cli`

`options.*` defines the command contract and produces a typed `Options` object. Long-only SealCheck options use dedicated enum values instead of overloading unrelated short flags.

`application.*` coordinates one of three workflows:

1. SealCheck preflight audit;
2. certificate or signed-binary diagnostics;
3. Mach-O or bundle signing and optional IPA packaging.

`main.cpp` only maps parse states to stable process exit codes.

### Core: `src/core`

The core layer contains the product behavior:

- `audit.*` discovers bundles, profiles, and Mach-O binaries and builds a typed audit report;
- `audit_report.cpp` serializes that report to text or schema-versioned JSON;
- `macho_file.*` owns file mappings and architecture slices for a Mach-O file;
- `macho_slice.*` parses and mutates one thin Mach-O architecture;
- `code_signature.*` reads and constructs embedded code-signature data;
- `signing_asset.*` loads certificates, keys, PKCS#12 material, profiles, entitlements, and CMS data;
- `app_bundle.*` traverses and signs app bundles and nested signable content;
- `certificate_check.*` provides certificate, profile, IPA, and signed-binary diagnostics;
- `metadata.*` extracts application metadata and icons.

Core APIs do not parse process arguments. Audit report structures in `audit.h` are plain data objects, which keeps scanning independent from presentation.

### Common: `src/common`

The common layer provides cross-cutting infrastructure:

- `file_system.*`: file I/O, mapping, path handling, and directory traversal;
- `zip_archive.*`: IPA/ZIP creation and defensive extraction;
- `json.*`: JSON and plist value handling;
- `hash.*`: digest operations;
- `logger.*`: process logging;
- `stopwatch.*`: operation timing;
- `utility.*`: string, byte-order, alignment, and process helpers;
- `base64.*`: base64 conversion.

Common code must not depend on signing-specific types.

### Platform and vendor code

Windows shims are compiled only on Windows. CMake downloads pinned zlib source and builds zlib plus its bundled minizip implementation as isolated static libraries. OpenSSL remains a system dependency discovered with CMake.

## SealCheck data flow

```text
CLI Options
    │
    ▼
audit::Request
    │
    ├── archive input ──► safe temporary extraction ──┐
    │                                                  │
    ├── bundle discovery and Info.plist validation     │
    ├── embedded/external profile parsing              │
    ├── read-only Mach-O mapping and slice inspection  │
    └── optional signing-asset compatibility checks    │
                                                       ▼
                                                 audit::Report
                                                       │
                               ┌───────────────────────┴───────────────────────┐
                               ▼                                               ▼
                         text renderer                                    JSON renderer
```

Archive extraction rejects absolute paths, drive-qualified paths, `..` components, alternate separators, unsafe control characters, and ambiguous trailing path syntax. Failed extraction removes the partial workspace.

Mach-O audit uses `MachOFile::InitReadOnly`. The mapping and its `MachOSlice` objects are owned by the `MachOFile` instance and released deterministically.

## Signing data flow

For an IPA, the CLI extracts to a temporary workspace, creates one or more `SigningAsset` objects, invokes `AppBundle::SignFolder`, and packages the resulting Payload only after signing succeeds. For a folder or single Mach-O, mutation occurs in place.

When a Mach-O needs a larger code-signature region, `MachOFile` builds replacement slices and validates the reconstructed file before deleting its backup. A failed replacement restores the original file.

## Error and exit model

Low-level legacy APIs generally return `bool` and log details through `Logger`. New SealCheck APIs use a typed report plus an explicit operational error string:

- findings belong in `Report::issues`;
- inability to perform the audit is returned through `Service::Run(..., error)`;
- serialization has no side effects;
- the CLI converts outcomes to documented exit codes.

Audit errors are different from operational failures. A successfully generated report may contain error-severity findings and therefore return exit code `3`.

## Extending SealCheck

A new check should:

1. add a stable uppercase issue code;
2. choose `Info`, `Warning`, or `Error` based on whether signing is structurally blocked;
3. attach the narrowest useful relative path;
4. avoid writing to the input;
5. update the JSON/text tests if the report contract changes;
6. increment `schemaVersion` only for a breaking report-shape change.

## Ownership and mutation invariants

- `MachOFile` exclusively owns its mapped file and `MachOSlice` objects. Inspection uses read-only mappings; signing explicitly requests writable mappings.
- `MachOSlice` keeps parser and signature state private. Public callers consume immutable summaries or narrowly scoped mutation methods.
- `SigningAsset` owns its OpenSSL key, certificate, and chain handles and exposes read-only metadata through accessors.
- `AppBundle` configuration is changed through named setters, not public mutable fields.
- Base64 and Windows text conversion use RAII-backed stable storage rather than caller-owned raw buffers.
- ZIP extraction and reconstructed Mach-O replacement are transactional: validation failure removes partial output or restores the original input.

## Test strategy

The public suite avoids private signing credentials. It combines small unit checks with end-to-end CLI fixtures:

- standard and binary Base64 vectors;
- little- and big-endian Mach-O dylib-command rebuilding;
- read-only Mach-O, app-bundle, and IPA SealCheck flows;
- text/JSON output, saved reports, and strict exit behavior;
- malformed load-command rejection;
- fail-closed ZIP traversal handling and cleanup.

Authorized private environments should add certificate/profile/signing integration tests without committing those assets.
