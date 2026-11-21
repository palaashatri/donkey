#!/bin/sh
# The R1 ratchet step of the r1 CI job (G20-T3), runnable locally:
#
#   sh tools/r1/ci-check.sh <base-commit> <r1-work> <head-build-dir> <out-dir>
#
# <r1-work> holds the R1 binaries (tools/r1/build.cmake) and <out-dir>/result.json their
# measurement by the head CLI. The check compares that with tools/r1/baseline.json as it is at
# <base-commit>, never with the file in the checkout. When some binary's bytes differ from the
# base baseline (a new compiler, source, flag or manifest), the base commit's donkey-cli is built
# in a worktree and measured on the same binaries, and the check is run again against it.
# Exit status: 0 pass, 3 the ratchet failed, anything else the step could not run.
set -eu

base=$1
work=$2
head_build=$3
out=$4
r1="$head_build/donkey-r1"

if git show "$base:tools/r1/baseline.json" > "$out/base-baseline.json" 2> /dev/null; then
  baseline="$out/base-baseline.json"
else
  echo "r1: $base has no tools/r1/baseline.json"
  baseline=none
fi

set +e
"$r1" check "$out/result.json" --baseline "$baseline" --head-baseline tools/r1/baseline.json
status=$?
set -e
if [ "$status" -ne 4 ]; then
  exit "$status"
fi

echo "r1: building donkey-cli at the base commit $base to measure the same bytes"
rm -rf "$out/base-src"
git worktree add --detach "$out/base-src" "$base"
cmake -S "$out/base-src" -B "$out/base-build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DDONKEY_BUILD_TESTS=OFF -DDONKEY_BUILD_R1_TOOL=OFF
cmake --build "$out/base-build" --parallel --target donkey-cli
# The head's decompile script and measure tool, with the base commit's CLI.
cmake -DR1_WORK="$work" -DDONKEY_CLI="$out/base-build/apps/donkey-cli/donkey-cli" \
  -DOUT="$out/decompiled-base" -P tools/r1/decompile.cmake
set +e
"$r1" measure "$work" "$out/decompiled-base" "$out/base-result.json" "$out/base-table.md"
measured=$?
set -e
if [ "$measured" -ne 0 ] && [ "$measured" -ne 2 ]; then
  exit "$measured"
fi
exec "$r1" check "$out/result.json" --baseline "$baseline" --head-baseline tools/r1/baseline.json \
  --base-result "$out/base-result.json"
