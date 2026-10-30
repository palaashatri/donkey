#!/bin/sh
# Build a FreeBSD binary package (.pkg) from an installed tree with pkg(8).
#
#   packaging/freebsd/make-pkg.sh <build-dir> <output-dir>
#
# Uses `cmake --install` into a staging root and `pkg create`, so it does
# not depend on CPack's optional libpkg support.
set -eu

build_dir=$1
out_dir=$2
src_dir=$(cd "$(dirname "$0")/../.." && pwd)
version=$(sed -n 's/^project(donkey VERSION \([0-9.]*\).*/\1/p' "$src_dir/CMakeLists.txt")
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# cmake --install honours DESTDIR for the staging root.
DESTDIR="$stage" cmake --install "$build_dir" --prefix /usr/local --strip --config Release

manifest="$stage/+MANIFEST"
cat > "$manifest" <<MANIFEST
name: donkey
version: "$version"
origin: devel/donkey
comment: "Native binary reverse-engineering workbench (alpha)"
www: "https://github.com/palaashatri/donkey"
maintainer: "donkey@users.noreply.github.com"
prefix: /usr/local
licenselogic: single
licenses: [MIT]
categories: [devel]
desc: <<EOD
Donkey opens ELF, PE and Mach-O binaries, disassembles x86, x86-64 and
AArch64 with Capstone, builds control-flow graphs, decompiles a verified IR
subset, stores annotations in SQLite projects and patches bytes safely.
Native process debugging is not available on FreeBSD yet. The desktop UI
needs an X11 or Wayland session; install libX11 and vulkan-loader for it.
EOD
MANIFEST

plist="$stage/pkg-plist"
(cd "$stage/usr/local" && find . -type f -o -type l | sed 's|^\./||' | sort) > "$plist"

mkdir -p "$out_dir"
pkg create -M "$manifest" -p "$plist" -r "$stage" -o "$out_dir"
ls -l "$out_dir"
