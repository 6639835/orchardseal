#!/usr/bin/env bash
set -euo pipefail

version="${1:-local}"
if [[ ! "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]]; then
    echo "Invalid version '$version'. Use letters, digits, dots, underscores, or hyphens." >&2
    exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "$script_dir/.." && pwd)"
package_name="OrchardSeal-${version}"
out_dir="$root_dir/dist"
archive="$out_dir/${package_name}.tar.gz"
checksum_file="${archive}.sha256"

sensitive_file="$({
    find "$root_dir" \
        \( -path "$root_dir/.git" -o -path "$root_dir/build" -o -path "$root_dir/dist" \) -prune -o \
        -type f \( -iname '*.p12' -o -iname '*.pfx' -o -iname '*.mobileprovision' -o -iname '*.ipa' \) \
        -print -quit
} || true)"
if [[ -n "$sensitive_file" ]]; then
    echo "Refusing to package potentially sensitive signing material: $sensitive_file" >&2
    exit 1
fi

mkdir -p "$out_dir"
temp_root="$(mktemp -d "${TMPDIR:-/tmp}/orchardseal-package.XXXXXX")"
trap 'rm -rf "$temp_root"' EXIT
stage_dir="$temp_root/$package_name"
mkdir -p "$stage_dir"

(
    cd "$root_dir"
    tar -cf - \
        --exclude='./.git' \
        --exclude='./build' \
        --exclude='./bin' \
        --exclude='./dist' \
        --exclude='./install' \
        --exclude='./.DS_Store' \
        .
) | (
    cd "$stage_dir"
    tar -xf -
)

tar -czf "$archive" -C "$temp_root" "$package_name"
digest="$(openssl dgst -sha256 "$archive" | awk '{print $NF}')"
printf '%s  %s\n' "$digest" "$(basename "$archive")" > "$checksum_file"

printf 'Created %s\n' "$archive"
printf 'Created %s\n' "$checksum_file"
