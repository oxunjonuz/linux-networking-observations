#!/bin/bash
# build_f45_differ.sh -- assemble and compile the turn-567 instrument.
#
# differ567.c is GENERATED: differ566.c (the F44 instrument, itself generated
# from the F43 one) with its main() renamed, plus vm/differ567_add.c.  Every
# helper under the new code -- netlink toolkit, veth/bridge/rtnetlink, NFLOG
# reader, AF_PACKET capture, counter read-back -- is byte-for-byte the one that
# produced F31..F44.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f566_main(int argc, char **argv)/' \
	vm/differ566.c > vm/differ567.c
grep -q '^int f566_main' vm/differ567.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ567.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ567_add.c >> vm/differ567.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ567 vm/differ567.c \
	2> logs/f45_gcc.log || { echo "GCC_FAIL"; tail -60 logs/f45_gcc.log; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f45_gcc.log || true)"
grep -v '^$' logs/f45_gcc.log | head -40 || true
ls -la vm/build/differ567
sha256sum vm/build/differ567 vm/differ567.c
