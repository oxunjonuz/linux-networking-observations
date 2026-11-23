#!/bin/bash
# build_f50_differ.sh -- assemble and compile the turn-573 instrument.
#
# differ573.c is GENERATED: differ572.c (the F49 instrument, itself generated
# from the F48 one) with its main() renamed to f571_main, plus
# vm/differ573_add.c, which supplies the new main() and mode `ll3br`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f572_entry(int argc, char **argv)/' \
	vm/differ572.c > vm/differ573.c
grep -q '^int f572_entry' vm/differ573.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ573.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ573_add.c >> vm/differ573.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ573 vm/differ573.c \
	2> logs/f51_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f51_gcc.log | head -80; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f51_gcc.log || true)"
grep -v '^$' logs/f51_gcc.log | head -60 || true
ls -la vm/build/differ573
sha256sum vm/build/differ573 vm/differ573.c
