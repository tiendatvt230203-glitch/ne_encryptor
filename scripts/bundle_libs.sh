#!/bin/sh
# Copy the few system .so files that "make" links against but are not
# already shipped in ./lib (so scp binary+lib/ to another host works).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
LIB="$ROOT/lib"
mkdir -p "$LIB"

copy_so() {
	# $1 = soname to create in lib/ (e.g. libbpf.so.1)
	src=$(ldconfig -p 2>/dev/null | awk -v s="$1" '$1 == s { print $NF; exit }')
	[ -n "$src" ] && [ -f "$src" ] || return 0
	real=$(readlink -f "$src")
	base=$(basename "$real")
	cp -f "$real" "$LIB/$base"
	ln -sfn "$base" "$LIB/$1"
	echo "bundle: $1 -> $base"
}

copy_so libbpf.so.1
copy_so libelf.so.1
copy_so libz.so.1
