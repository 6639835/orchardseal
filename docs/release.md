# OrchardSeal release process

## 1. Prepare

- Confirm the intended version in `project(OrchardSeal VERSION ...)`.
- Update `CHANGELOG.md` and any report-schema documentation.
- Confirm no private keys, certificates, provisioning profiles, customer applications, or signed IPA files are present.

## 2. Validate from a clean tree

```bash
rm -rf build/release-final
cmake -S . -B build/release-final \
  -DCMAKE_BUILD_TYPE=Release \
  -DORCHARDSEAL_BUILD_TESTS=ON \
  -DORCHARDSEAL_WARNINGS_AS_ERRORS=ON
cmake --build build/release-final --parallel
ctest --test-dir build/release-final --output-on-failure
```

Also verify the public contract:

```bash
build/release-final/orchardseal --version
build/release-final/orchardseal --help
build/release-final/orchardseal --audit --audit-format json \
  tests/fixtures/macho/arm64-executable
```

Run private signing integration tests with authorized assets outside the repository.

## 3. Package and publish

Pushing an annotated `vX.Y.Z` tag triggers the release workflow. It validates the
tag against `project(OrchardSeal VERSION ...)`, builds with warnings treated as
errors, runs CTest, creates the source archive and checksum, and publishes both
to the GitHub release.

You can still inspect a package locally before tagging:

```bash
scripts/package.sh X.Y.Z
```

Ensure the archive contains source, documentation, tests, and license files but no build directory or sensitive material.

## 4. Tag and publish

```bash
git tag -a vX.Y.Z -m "OrchardSeal X.Y.Z"
git push origin vX.Y.Z
```

The workflow publishes checksums alongside release archives. Document any JSON schema change, new issue code, signing-output change, or supported-platform change in the release notes before pushing the tag.

## Compatibility rules

- Adding JSON fields is compatible within schema `1.x`.
- Removing or renaming fields requires a schema-version change.
- New issue codes are compatible but must be documented.
- Changes that alter generated signatures or bundle mutation order require focused integration testing.
- Public CLI option removal requires a deprecation period unless the release is explicitly marked breaking.
