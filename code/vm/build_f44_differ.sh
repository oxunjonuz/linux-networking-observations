#!/bin/bash
# build_f44_differ.sh -- assemble and compile the turn-566 instrument.
#
# differ566.c is GENERATED: differ565.c (the F43 instrument, itself generated
# from the F42 one) with its main() renamed, plus vm/differ566_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back, frame builders, the PPP unit
# and the PPPoX socket -- is byte-for-byte the one that produced F31..F43.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f565_main(int argc, char **argv)/' \
	vm/differ565.c > vm/differ566.c
grep -q '^int f565_main' vm/differ566.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ566.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ566_add.c >> vm/differ566.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ566 vm/differ566.c \
	2> logs/f44_gcc.log || { echo "GCC_FAIL"; tail -60 logs/f44_gcc.log; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f44_gcc.log || true)"
grep -v '^$' logs/f44_gcc.log | head -30 || true
ls -la vm/build/differ566
sha256sum vm/build/differ566 vm/differ566.c
