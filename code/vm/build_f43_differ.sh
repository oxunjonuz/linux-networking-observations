#!/bin/bash
# build_f43_differ.sh -- assemble and compile the turn-565 instrument.
#
# differ565.c is GENERATED: differ564.c (the F42 instrument, itself generated
# from the F41 one) with its main() renamed, plus vm/differ565_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back, frame builders, the PPP unit
# and the PPPoX socket -- is byte-for-byte the one that produced F31..F42.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f564_main(int argc, char **argv)/' \
	vm/differ564.c > vm/differ565.c
grep -q '^int f564_main' vm/differ565.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ565_add.c >> vm/differ565.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ565 vm/differ565.c \
	2> logs/f43_gcc.log || { echo "GCC_FAIL"; tail -60 logs/f43_gcc.log; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f43_gcc.log || true)"
grep -v '^$' logs/f43_gcc.log | head -30 || true
ls -la vm/build/differ565
sha256sum vm/build/differ565 vm/differ565.c
