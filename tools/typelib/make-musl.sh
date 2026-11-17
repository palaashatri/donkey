#!/bin/sh
# Generates the musl 1.2.4 type library (G22-T2) from the headers of the Ubuntu/Debian musl-dev
# package, version 1.2.4-2. The headers are not copied into the repository: the library records
# each header's path and SHA-256, the preprocessor command and the licence.
#
#   sh tools/typelib/make-musl.sh path/to/donkey-cli [out.dtl]
#
# Licence: the musl package is MIT; its public headers (include/*) are public domain with an
# explicit permission grant (/usr/share/doc/musl-dev/copyright). The owner allowed musl as a type
# library source on 2026-11-17 (docs/IDA_GAP_LEDGER.md, G22-T2). The preprocessor runs here, at
# build time, never when Donkey runs. CREATED (YYYY-MM-DD) fixes the date for a reproducible file.
set -eu

cli=${1:?usage: make-musl.sh path/to/donkey-cli [out.dtl]}
out=${2:-typelibs/musl-1.2.4-x86_64-linux.dtl}
include=/usr/include/x86_64-linux-musl
licence=/usr/share/doc/musl-dev/copyright
created=${CREATED:-$(date -u +%Y-%m-%d)}

version=$(dpkg-query -W -f='${Version}' musl-dev 2>/dev/null || true)
if [ "$version" != "1.2.4-2" ]; then
  echo "make-musl.sh: needs musl-dev 1.2.4-2 (found '${version:-none}')" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Every top-level header, except the ones that only redirect to another (they warn and add
# nothing), in name order.
set --
for header in $(cd "$include" && ls ./*.h | sed 's|^\./||' | LC_ALL=C sort); do
  if grep -q '#warning redirecting' "$include/$header"; then
    continue
  fi
  echo "#include <$header>" >> "$work/all.c"
  set -- "$@" --source-file "$header $(sha256sum "$include/$header" | cut -d' ' -f1)"
done

cpp="gcc -E -P -nostdinc -isystem $include -D_GNU_SOURCE"
$cpp "$work/all.c" -o "$work/all.i"

"$cli" typelib make "$work/all.i" --out "$out" \
  --library musl-libc --library-version 1.2.4 \
  --platform linux --architecture x86_64 --abi sysv --data-model LP64 --char-signed true \
  --source "musl-dev 1.2.4-2 (Ubuntu 24.04), headers in $include" \
  --source-sha256 "$(sha256sum "$work/all.i" | cut -d' ' -f1)" \
  --licence MIT \
  --licence-file usr/share/doc/musl-dev/copyright \
  --licence-sha256 "$(sha256sum "$licence" | cut -d' ' -f1)" \
  --command "sh tools/typelib/make-musl.sh" \
  --preprocessor "gcc $(gcc -dumpfullversion) -E -P -nostdinc -D_GNU_SOURCE" \
  --created "$created" \
  --macro _GNU_SOURCE= \
  --note "source_sha256 is the SHA-256 of the preprocessed text; each source_file is a musl header" \
  --note "musl include/* is public domain with a permission grant; the package licence is MIT" \
  "$@"
