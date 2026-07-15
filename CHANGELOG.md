# Changelog

All notable changes to OrchardSeal are documented here. The project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and Semantic
Versioning.

## [Unreleased]

### Security

- Hardened archive, Mach-O, signature, certificate, process-launch, and release
  packaging boundaries so malformed or untrusted inputs fail closed.
- Redacted signing passwords from debug logs and isolated diagnostics from
  machine-readable standard output.

### Changed

- Source releases are reproducible archives of a clean committed tree and use a
  strict tracked-file allowlist.
- CMake 3.25 is now the minimum supported version.

## [0.2.0]

### Added

- SealCheck read-only signing audits with text and JSON reports.
- Cross-platform CMake builds, credential-free public tests, and release
  automation.

## [0.1.0]

### Added

- Initial portable iOS signing, Mach-O inspection, and IPA packaging support.
