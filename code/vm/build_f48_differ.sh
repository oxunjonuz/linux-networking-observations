#!/bin/bash
# build_f48_differ.sh -- assemble and compile the turn-570 instrument.
#
# differ570.c is GENERATED: differ569.c (the F47 instrument, itself generated
# from the F46 one) with its main() renamed to f569_main, plus
# vm/differ570_add.c.  Every helper under the new code is the one that produced
# F31..F47.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f569_main(int argc, char **argv)/' \
	vm/differ569.c > vm/differ570.c
grep -q '^int f569_main' vm/differ570.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ570.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ570_add.c >> vm/differ570.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ570 vm/differ570.c \
	2> logs/f48_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f48_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f48_gcc.log || true)"
grep -v '^$' logs/f48_gcc.log | head -40 || true
ls -la vm/build/differ570
sha256sum vm/build/differ570 vm/differ570.c
