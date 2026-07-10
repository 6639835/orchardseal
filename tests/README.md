# OrchardSeal tests

The public suite is intentionally credential-free and uses synthetic or non-sensitive fixtures.

## Registered CTest coverage

- `orchardseal.base64`: validates standard vectors, binary round trips, tolerant decoding, and stable result storage.
- `orchardseal.macho-slice`: validates bounded dylib-command removal and reparsing for little- and big-endian Mach-O images.
- `orchardseal.version`: verifies the public version entry point.
- `orchardseal.help`: verifies CLI help generation.
- `orchardseal.audit-smoke`: exercises Mach-O, `.app`, and `.ipa` SealCheck paths; text/JSON behavior; saved reports; and strict exit code `3`.
- `orchardseal.archive-safety`: verifies that a traversal archive is rejected, cannot write outside its extraction root, and leaves no partial workspace.
- `orchardseal.malformed-macho`: rejects an invalid load-command table and verifies the audit fails safely.

Run:

```bash
cmake -S . -B build/release \
  -DCMAKE_BUILD_TYPE=Release \
  -DORCHARDSEAL_BUILD_TESTS=ON \
  -DORCHARDSEAL_WARNINGS_AS_ERRORS=ON
cmake --build build/release --parallel
ctest --test-dir build/release --output-on-failure
```

## Fixtures

- `fixtures/macho/arm64-executable`: a small arm64 Mach-O header/signature fixture used for read-only inspection.
- `fixtures/macho/malformed-load-command`: a deliberately invalid Mach-O used to exercise parser bounds checks.
- `fixtures/dylib/`: dylib fixtures retained for injection and parser integration work.
- `fixtures/archives/path-traversal.zip`: a deliberately malicious archive used only to verify fail-closed extraction.

Do not extract the malicious fixture with unrelated tools into a sensitive working directory.

## Private signing integration tests

Real signing tests require authorized local assets. Suggested ignored locations are:

```text
tests/assets/test.p12
tests/assets/test.mobileprovision
tests/ipa/*.ipa
```

Never commit those files. The platform scripts under `tests/fixtures/*/` accept environment-variable overrides for private test environments.
