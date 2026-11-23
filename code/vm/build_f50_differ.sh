#!/bin/bash
# build_f50_differ.sh -- assemble and compile the turn-572 instrument.
#
# differ572.c is GENERATED: differ571.c (the F49 instrument, itself generated
# from the F48 one) with its main() renamed to f571_main, plus
# vm/differ572_add.c, which supplies the new main() and mode `ll3br`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f571_entry(int argc, char **argv)/' \
	vm/differ571.c > vm/differ572.c
grep -q '^int f571_entry' vm/differ572.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ572.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ572_add.c >> vm/differ572.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ572 vm/differ572.c \
	2> logs/f50_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f50_gcc.log | head -80; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f50_gcc.log || true)"
grep -v '^$' logs/f50_gcc.log | head -60 || true
ls -la vm/build/differ572
sha256sum vm/build/differ572 vm/differ572.c
