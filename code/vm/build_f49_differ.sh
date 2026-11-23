#!/bin/bash
# build_f49_differ.sh -- assemble and compile the turn-571 instrument.
#
# differ571.c is GENERATED: differ570.c (the F48 instrument, itself generated
# from the F47 one) with its main() renamed to f570_main, plus
# vm/differ571_add.c, which supplies the new main() and mode `pp6l3`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f570_main(int argc, char **argv)/' \
	vm/differ570.c > vm/differ571.c
grep -q '^int f570_main' vm/differ571.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ571.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ571_add.c >> vm/differ571.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ571 vm/differ571.c \
	2> logs/f49_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f49_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f49_gcc.log || true)"
grep -v '^$' logs/f49_gcc.log | head -40 || true
ls -la vm/build/differ571
sha256sum vm/build/differ571 vm/differ571.c
