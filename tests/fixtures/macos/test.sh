#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

PACKAGES="${PACKAGES:-$ROOT_DIR/tests/ipa}"
PRIVATE_KEY="${PRIVATE_KEY:-$ROOT_DIR/tests/assets/test.p12}"
MOBILE_PROVISION="${MOBILE_PROVISION:-$ROOT_DIR/tests/assets/test.mobileprovision}"
ORCHARDSEAL_BIN="${ORCHARDSEAL_BIN:-$ROOT_DIR/build/release/orchardseal}"

if [[ ! -x "$ORCHARDSEAL_BIN" ]]; then
    echo "orchardseal binary not found: $ORCHARDSEAL_BIN" >&2
    exit 1
fi

if [[ ! -f "$PRIVATE_KEY" || ! -f "$MOBILE_PROVISION" ]]; then
    echo "private signing assets not found; set PRIVATE_KEY and MOBILE_PROVISION" >&2
    exit 1
fi

shopt -s nullglob
packages=("$PACKAGES"/*.ipa)
if (( ${#packages[@]} == 0 )); then
    echo "no IPA inputs found in $PACKAGES" >&2
    exit 1
fi

output_dir="$(mktemp -d "${TMPDIR:-/tmp}/orchardseal-macos-signing.XXXXXX")"
trap 'rm -rf "$output_dir"' EXIT HUP INT TERM
failed=0
for file in "${packages[@]}"; do
    output_file="$output_dir/$(basename "$file")"
    printf '%s: ' "$file"
    if "$ORCHARDSEAL_BIN" -q -U -k "$PRIVATE_KEY" -m "$MOBILE_PROVISION" -o "$output_file" "$file" \
        >/dev/null 2>&1 && [[ -s "$output_file" ]]; then
        printf '\033[32mOK.\033[0m\n'
    else
        printf '\033[31mFAILED.\033[0m\n'
        failed=1
    fi
done
exit "$failed"
