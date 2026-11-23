#!/bin/bash
# build_f37_differ.sh -- assemble and compile the turn-559 instrument.
#
# differ559.c is GENERATED: differ558.c (the F36 instrument, itself generated
# from the F35 one) with its main() renamed, plus vm/differ559_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back, the frame builders -- is
# byte-for-byte the one that produced F30..F36.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f558_main(int argc, char **argv)/' \
	vm/differ558.c > vm/differ559.c
grep -q '^int f558_main' vm/differ559.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ559_add.c >> vm/differ559.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ559 vm/differ559.c \
	2> logs/f37_gcc.log || { echo "GCC_FAIL"; tail -40 logs/f37_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f37_gcc.log)"
head -40 logs/f37_gcc.log
ls -la vm/build/differ559
sha256sum vm/build/differ559 vm/differ559.c
