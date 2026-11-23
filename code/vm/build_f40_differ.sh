#!/bin/bash
# build_f40_differ.sh -- assemble and compile the turn-562 instrument.
#
# differ562.c is GENERATED: differ561.c (the F39 instrument, itself generated
# from the F38 one) with its main() renamed, plus vm/differ562_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back, frame builders -- is
# byte-for-byte the one that produced F31..F39.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f561_main(int argc, char **argv)/' \
	vm/differ561.c > vm/differ562.c
grep -q '^int f561_main' vm/differ562.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ562_add.c >> vm/differ562.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ562 vm/differ562.c \
	2> logs/f40_gcc.log || { echo "GCC_FAIL"; tail -40 logs/f40_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f40_gcc.log)"
head -20 logs/f40_gcc.log
ls -la vm/build/differ562
sha256sum vm/build/differ562 vm/differ562.c
