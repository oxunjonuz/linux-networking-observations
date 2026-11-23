#!/bin/bash
# build_f41_differ.sh -- assemble and compile the turn-563 instrument.
#
# differ563.c is GENERATED: differ562.c (the F40 instrument, itself generated
# from the F39 one) with its main() renamed, plus vm/differ563_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back, frame builders -- is
# byte-for-byte the one that produced F31..F40.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f562_main(int argc, char **argv)/' \
	vm/differ562.c > vm/differ563.c
grep -q '^int f562_main' vm/differ563.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ563_add.c >> vm/differ563.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ563 vm/differ563.c \
	2> logs/f41_gcc.log || { echo "GCC_FAIL"; tail -40 logs/f41_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f41_gcc.log)"
head -20 logs/f41_gcc.log
ls -la vm/build/differ563
sha256sum vm/build/differ563 vm/differ563.c
