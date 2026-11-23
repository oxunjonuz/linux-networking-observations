#!/bin/bash
# build_f71_differ.sh -- assemble and compile the turn-593 instrument (F71).
#
# differ593.c is GENERATED: differ592.c (the F70 instrument, which already
# carries f591_entry) with its main() renamed to f592_entry, plus
# vm/differ593_add.c, which supplies the new main() and mode `gro`:
# a paged GRO aggregate delivered whole to a UDP_GRO socket, so that
# skb_condense()'s first clause becomes a cell at the byte.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f592_entry(int argc, char **argv)/' \
	vm/differ592.c > vm/differ593.c
grep -q '^int f592_entry' vm/differ593.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ593_add.c >> vm/differ593.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ593.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ593 vm/differ593.c \
	2> logs/f71_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f71_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -c 'warning:' logs/f71_gcc.log || true)"
grep "error:" logs/f71_gcc.log | head -20 || true
ls -la vm/build/differ593
sha256sum vm/build/differ593 vm/differ593.c vm/differ593_add.c
