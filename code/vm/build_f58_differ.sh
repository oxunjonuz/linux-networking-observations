#!/bin/bash
# build_f58_differ.sh -- assemble and compile the turn-580 instrument (F58).
#
# differ580.c is GENERATED: differ579.c (the F57 instrument, itself generated
# from differ578) with its main() renamed to f579_entry, plus
# vm/differ580_add.c, which supplies the new main() and mode `bounds`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f579_entry(int argc, char **argv)/' \
	vm/differ579.c > vm/differ580.c
grep -q '^int f579_entry' vm/differ580.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ580.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ580_add.c >> vm/differ580.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ580 vm/differ580.c \
	2> logs/f58_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f58_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f58_gcc.log || true)"
grep -v '^$' logs/f58_gcc.log | head -40 || true
ls -la vm/build/differ580
sha256sum vm/build/differ580 vm/differ580.c
