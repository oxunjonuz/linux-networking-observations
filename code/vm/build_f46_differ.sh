#!/bin/bash
# build_f46_differ.sh -- assemble and compile the turn-568 instrument.
#
# differ568.c is GENERATED: differ567.c (the F45 instrument) with its main()
# renamed to f567_main, plus vm/differ568_add.c.  Every helper under the new
# code -- netlink toolkit, veth/rtnetlink, NFLOG reader, AF_PACKET capture,
# counter read-back, chain install -- is byte-for-byte the one that produced
# F31..F45.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f567_main(int argc, char **argv)/' \
	vm/differ567.c > vm/differ568.c
grep -q '^int f567_main' vm/differ568.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ568.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ568_add.c >> vm/differ568.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ568 vm/differ568.c \
	2> logs/f46_gcc.log || { echo "GCC_FAIL"; tail -60 logs/f46_gcc.log; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f46_gcc.log || true)"
grep -v '^$' logs/f46_gcc.log | head -60 || true
ls -la vm/build/differ568
sha256sum vm/build/differ568 vm/differ568.c
