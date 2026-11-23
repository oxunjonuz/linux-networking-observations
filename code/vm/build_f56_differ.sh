#!/bin/bash
# build_f56_differ.sh -- assemble and compile the turn-578 instrument.
#
# differ578.c is GENERATED: differ576.c (the F54 instrument, itself generated)
# with its main() renamed to f576_entry, plus vm/differ578_add.c, which
# supplies the new main() and modes `ad` and `br`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f576_entry(int argc, char **argv)/' \
	vm/differ576.c > vm/differ578.c
grep -q '^int f576_entry' vm/differ578.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ578.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ578_add.c >> vm/differ578.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ578 vm/differ578.c \
	2> logs/f56_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f56_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f56_gcc.log || true)"
grep -v '^$' logs/f56_gcc.log | head -40 || true
ls -la vm/build/differ578
sha256sum vm/build/differ578 vm/differ578.c
