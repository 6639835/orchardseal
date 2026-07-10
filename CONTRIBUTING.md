# Contributing to OrchardSeal

## Development build

```bash
cmake -S . -B build/debug \
  -DCMAKE_BUILD_TYPE=Debug \
  -DORCHARDSEAL_BUILD_TESTS=ON \
  -DORCHARDSEAL_WARNINGS_AS_ERRORS=ON
cmake --build build/debug --parallel
ctest --test-dir build/debug --output-on-failure
```

## Code boundaries

- Keep argument parsing and process behavior in `src/cli`.
- Keep signing, Mach-O, bundle, provisioning, certificate, and SealCheck logic in `src/core`.
- Keep generic reusable infrastructure in `src/common`.
- Keep Windows-only compatibility code under `src/platform/windows`.
- Do not mix vendored zlib/minizip edits with OrchardSeal refactors.

## Style

- Use C++17 and the repository `.clang-format` configuration.
- Prefer clear responsibility-based names over abbreviations and Hungarian notation in new code.
- Prefer RAII and standard containers for owned resources.
- Mark non-mutating queries `const` and `[[nodiscard]]` when ignoring the result is likely a defect.
- Keep read-only inspection separate from mutation APIs.
- Avoid hidden logging in query methods; findings should be returned as data where practical.
- Preserve existing signing output unless a change explicitly documents and tests the compatibility impact.

## SealCheck checks

Each new finding needs:

- a stable uppercase issue code;
- a clear severity choice;
- an actionable message;
- a relevant relative path;
- text/JSON compatibility consideration;
- a test fixture or test-script assertion.

Do not use an error-severity finding for a policy preference that does not structurally prevent signing. `--strict-audit` exists so callers can promote warnings without changing the report semantics.

## Pull request checklist

1. Build with warnings as errors.
2. Run all CTest tests.
3. Add or update tests for user-visible behavior.
4. Update the changelog and documentation when the CLI, report schema, issue codes, signing behavior, or supported platforms change.
5. Confirm no credentials, profiles, customer apps, signed IPAs, build outputs, or debug artifacts are included.
6. Keep commits focused and explain any change to generated signature bytes or bundle traversal order.
