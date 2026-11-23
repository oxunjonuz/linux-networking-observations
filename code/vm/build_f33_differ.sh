#!/bin/bash
# build_f33_differ.sh -- assemble and compile the turn-556 instrument.
#
# differ556.c is GENERATED, not hand-edited: it is differ555.c (the F32
# instrument: netlink toolkit, veth/rtnetlink, NFLOG reader, ARP frame
# builder, counter read-back) with its main() renamed, plus
# vm/differ556_add.c (this turn's envelopes and grid).  Generating it this way
# means the helpers under the new code are byte-for-byte the ones that already
# produced F30/F31/F32 numbers, and the diff of the instrument is exactly the
# new section of code.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f555_main(int argc, char **argv)/' \
	vm/differ555.c > vm/differ556.c
grep -q '^int f555_main' vm/differ556.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ556_add.c >> vm/differ556.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ556 vm/differ556.c \
	2> logs/f33_gcc.log || { echo "GCC_FAIL"; tail -20 logs/f33_gcc.log; exit 1; }
echo "gcc_warnings=$(wc -l < logs/f33_gcc.log)"
ls -la vm/build/differ556
sha256sum vm/build/differ556 vm/differ556.c
