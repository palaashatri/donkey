#!/bin/sh
# Measures the stack one level of the type library comparison takes (ShapeComparer::same and
# ::same_definition in src/project/typelib_apply.cpp) with this host's compiler, at -O3, -O0 and -O0
# with ASan, and fails when kMaxDepth levels of the worst build exceed 256 KiB: half the smallest
# default stack of a thread Donkey runs on (512 KiB, macOS secondary threads), the rest left to the
# callers. Run from the repository root; CXX names the compiler (default c++).
set -eu
cxx=${CXX:-c++}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
depth=$(sed -n 's/.*kMaxDepth = \([0-9][0-9]*\);.*/\1/p' src/project/typelib_apply.cpp)
[ -n "$depth" ] || { echo "kMaxDepth not found" >&2; exit 1; }
"$cxx" --version | head -1
worst=0
for flags in "-O3" "-O0" "-O0 -fsanitize=address"; do
  # shellcheck disable=SC2086
  (cd "$work" && "$cxx" -std=c++20 $flags -fstack-usage -I"$OLDPWD/include" \
    -c "$OLDPWD/src/project/typelib_apply.cpp" -o typelib_apply.o)
  level=$(grep -E 'ShapeComparer[^	]*(4same|15same_definition|::same\(|::same_definition\()' \
    "$work/typelib_apply.su" | awk -F'\t' '{ sum += $2 } END { print sum + 0 }')
  [ "$level" -gt 0 ] || { echo "no ShapeComparer frames in the stack usage report" >&2; exit 1; }
  echo "$flags: $level bytes per level, $((level * depth / 1024)) KiB for $depth levels"
  [ "$level" -gt "$worst" ] && worst=$level
done
limit=$((256 * 1024))
if [ $((worst * depth)) -gt "$limit" ]; then
  echo "kMaxDepth $depth levels take $((worst * depth)) bytes, over $limit" >&2
  exit 1
fi
