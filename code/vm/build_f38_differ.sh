#!/bin/bash
# build_f38_differ.sh -- assemble and compile the turn-560 instrument.
#
# differ560.c is GENERATED: differ559.c (the F37 instrument, itself generated
# from the F36 one) with its main() renamed, plus vm/differ560_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back, the frame builders, the ethtool
# bit -- is byte-for-byte the one that produced F31..F37.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f559_main(int argc, char **argv)/' \
	vm/differ559.c > vm/differ560.c
grep -q '^int f559_main' vm/differ560.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ560_add.c >> vm/differ560.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ560 vm/differ560.c \
	2> logs/f38_gcc.log || { echo "GCC_FAIL"; tail -40 logs/f38_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f38_gcc.log)"
head -40 logs/f38_gcc.log
ls -la vm/build/differ560
sha256sum vm/build/differ560 vm/differ560.c
