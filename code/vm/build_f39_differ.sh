#!/bin/bash
# build_f39_differ.sh -- assemble and compile the turn-561 instrument.
#
# differ561.c is GENERATED: differ560.c (the F38 instrument, itself generated
# from the F37 one) with its main() renamed, plus vm/differ561_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back, frame builders, the ethtool
# feature ioctl -- is byte-for-byte the one that produced F31..F38.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f560_main(int argc, char **argv)/' \
	vm/differ560.c > vm/differ561.c
grep -q '^int f560_main' vm/differ561.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ561_add.c >> vm/differ561.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ561 vm/differ561.c \
	2> logs/f39_gcc.log || { echo "GCC_FAIL"; tail -40 logs/f39_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f39_gcc.log)"
head -20 logs/f39_gcc.log
ls -la vm/build/differ561
sha256sum vm/build/differ561 vm/differ561.c
