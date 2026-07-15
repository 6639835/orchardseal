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

if ! git -C "$root_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Source packages must be created from a Git checkout." >&2
    exit 1
fi

if [[ -n "$(git -C "$root_dir" status --porcelain --untracked-files=normal)" ]]; then
    echo "Refusing to package a dirty working tree. Commit or remove tracked and non-ignored changes first." >&2
    exit 1
fi

invalid_path=""
shopt -s nocasematch
while IFS= read -r -d '' path; do
    case "$path" in
        *$'\n'*|*$'\r'*|*$'\t'*)
            invalid_path="$path"
            break
            ;;
    esac
    case "$path" in
        .clang-format|.clang-tidy|.dockerignore|.editorconfig|.gitattributes|.gitignore|\
        CMakeLists.txt|CMakePresets.json|CONTRIBUTING.md|Dockerfile|LICENSE|Makefile|README.md|SECURITY.md|CHANGELOG.md|\
        cmake/*|docs/*|include/*|scripts/*|src/*|tests/*|.github/*)
            ;;
        *)
            invalid_path="$path"
            break
            ;;
    esac

    case "/$path/" in
        */tests/assets/*|*/tests/ipa/*|*/tests/packages/*|*.p8/*|*.p12/*|*.pfx/*|*.pk8/*|*.pkcs8/*|\
        *.pkcs12/*|*.mobileprovision/*|*.provisionprofile/*|*.pem/*|*.key/*|*.jks/*|*.keystore/*|\
        *.cer/*|*.crt/*|*.der/*|*.ipa/*|*/.env/*|*/.env.*/*|*.credentials/*|*.secrets/*|*.token/*|\
        *.log/*|*.core/*|*.dump/*|*.dSYM/*|*/.orchardseal_cache/*|\
        */.orchardseal_debug/*)
            invalid_path="$path"
            break
            ;;
    esac
    case "${path##*/}" in
        core|core.[0-9]*)
            invalid_path="$path"
            break
            ;;
    esac
done < <(git -C "$root_dir" ls-tree -rz --name-only HEAD)

if [[ -n "$invalid_path" ]]; then
    echo "Refusing tracked path outside the source allowlist or denied as sensitive/runtime data: $invalid_path" >&2
    exit 1
fi

mkdir -p "$out_dir"
temp_root="$(mktemp -d "$out_dir/.orchardseal-package.XXXXXX")"
trap 'rm -rf "$temp_root"' EXIT HUP INT TERM
temporary_archive="$temp_root/${package_name}.tar.gz"
temporary_checksum="${temporary_archive}.sha256"
deterministic_gzip="$temp_root/deterministic-gzip"

git -C "$root_dir" archive --format=tar --prefix="${package_name}/" HEAD > "$temp_root/source.tar"

IFS=' ' read -r -a cxx_command <<< "${CXX:-c++}"
if [[ "${#cxx_command[@]}" -eq 0 ]] || ! command -v "${cxx_command[0]}" >/dev/null 2>&1; then
    echo "A C++17 compiler is required to create deterministic source packages." >&2
    exit 1
fi
"${cxx_command[@]}" -std=c++17 -O2 "$script_dir/deterministic_gzip.cpp" -o "$deterministic_gzip"
"$deterministic_gzip" "$temp_root/source.tar" "$temporary_archive"

digest="$(openssl dgst -sha256 "$temporary_archive" | awk '{print $NF}')"
printf '%s  %s\n' "$digest" "$(basename "$archive")" > "$temporary_checksum"
mv -f "$temporary_archive" "$archive"
mv -f "$temporary_checksum" "$checksum_file"

printf 'Created %s\n' "$archive"
printf 'Created %s\n' "$checksum_file"
