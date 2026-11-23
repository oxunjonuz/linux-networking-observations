#!/bin/bash
# build_f42_differ.sh -- assemble and compile the turn-564 instrument.
#
# differ564.c is GENERATED: differ563.c (the F41 instrument, itself generated
# from the F40 one) with its main() renamed, plus vm/differ564_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back, frame builders, the PPPoX
# socket -- is byte-for-byte the one that produced F31..F41.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f563_main(int argc, char **argv)/' \
	vm/differ563.c > vm/differ564.c
grep -q '^int f563_main' vm/differ564.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ564_add.c >> vm/differ564.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ564 vm/differ564.c \
	2> logs/f42_gcc.log || { echo "GCC_FAIL"; tail -60 logs/f42_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f42_gcc.log)"
grep -v '^$' logs/f42_gcc.log | head -30 || true
ls -la vm/build/differ564
sha256sum vm/build/differ564 vm/differ564.c
