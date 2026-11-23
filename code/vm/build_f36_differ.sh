#!/bin/bash
# build_f36_differ.sh -- assemble and compile the turn-558 instrument.
#
# differ558.c is GENERATED: differ557.c (the F35 instrument, itself generated
# from the F33 one) with its main() renamed, plus vm/differ558_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET, counter read-back, the fast install path, the four frame
# builders -- is byte-for-byte the one that produced F30..F35.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f557_main(int argc, char **argv)/' \
	vm/differ557.c > vm/differ558.c
grep -q '^int f557_main' vm/differ558.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ558_add.c >> vm/differ558.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ558 vm/differ558.c \
	2> logs/f36_gcc.log || { echo "GCC_FAIL"; tail -40 logs/f36_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f36_gcc.log)"
head -40 logs/f36_gcc.log
ls -la vm/build/differ558
sha256sum vm/build/differ558 vm/differ558.c
