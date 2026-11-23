#!/bin/bash
# build_f59_differ.sh -- assemble and compile the turn-581 instrument (F59).
#
# differ581.c is GENERATED: differ580.c (the F58 instrument, itself generated
# from differ579) with its main() renamed to f580_entry, plus
# vm/differ581_add.c, which supplies the new main() and mode `guard`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f580_entry(int argc, char **argv)/' \
	vm/differ580.c > vm/differ581.c
grep -q '^int f580_entry' vm/differ581.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ581.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ581_add.c >> vm/differ581.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ581 vm/differ581.c \
	2> logs/f59_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f59_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f59_gcc.log || true)"
grep -v '^$' logs/f59_gcc.log | head -40 || true
ls -la vm/build/differ581
sha256sum vm/build/differ581 vm/differ581.c
