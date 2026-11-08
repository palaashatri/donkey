#!/bin/sh
# Regenerates the MSVC demangler corpus (G10-T2) from names.cpp. The expected text is what
# llvm-undname prints for each symbol clang emits for the x86-64 Windows target. Run it from
# any directory; it writes msvc-pairs.txt next to this script. See PROVENANCE.md.
set -eu
dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
clang++ --target=x86_64-pc-windows-msvc -fno-exceptions -fno-rtti -c "$dir/names.cpp" -o "$tmp/names.obj"
llvm-nm "$tmp/names.obj" | awk '{print $NF}' | grep '^?' | sort -u > "$tmp/names.txt"
: > "$dir/msvc-pairs.txt"
while IFS= read -r name; do
  expected=$(llvm-undname "$name" | sed -n 2p)
  printf '%s\t%s\n' "$name" "$expected" >> "$dir/msvc-pairs.txt"
done < "$tmp/names.txt"
