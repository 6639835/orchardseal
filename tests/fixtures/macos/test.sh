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

shopt -s nullglob
for file in "$PACKAGES"/*.ipa; do
    printf '%s: ' "$file"
    if "$ORCHARDSEAL_BIN" -q -U -k "$PRIVATE_KEY" -m "$MOBILE_PROVISION" "$file" >/dev/null 2>&1; then
        printf '\033[32mOK.\033[0m\n'
    else
        printf '\033[31mFAILED.\033[0m\n'
    fi
done
