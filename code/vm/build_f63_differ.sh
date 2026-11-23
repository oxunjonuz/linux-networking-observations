#!/bin/bash
# build_f63_differ.sh -- assemble and compile the turn-585 instrument (F63).
#
# differ585.c is GENERATED: differ584.c (the F62 instrument, itself generated
# from differ583) with its main() renamed to f584_entry, plus
# vm/differ585_add.c, which supplies the new main() and mode `aggr`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f584_entry(int argc, char **argv)/' \
	vm/differ584.c > vm/differ585.c
grep -q '^int f584_entry' vm/differ585.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ585.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ585_add.c >> vm/differ585.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ585 vm/differ585.c \
	2> logs/f63_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f63_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f63_gcc.log || true)"
grep -v '^$' logs/f63_gcc.log | head -40 || true
ls -la vm/build/differ585
sha256sum vm/build/differ585 vm/differ585.c
