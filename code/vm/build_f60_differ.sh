#!/bin/bash
# build_f60_differ.sh -- assemble and compile the turn-582 instrument (F60).
#
# differ582.c is GENERATED: differ581.c (the F59 instrument, itself generated
# from differ580) with its main() renamed to f581_entry, plus
# vm/differ582_add.c, which supplies the new main() and modes `part` / `opt`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f581_entry(int argc, char **argv)/' \
	vm/differ581.c > vm/differ582.c
grep -q '^int f581_entry' vm/differ582.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ582.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ582_add.c >> vm/differ582.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ582 vm/differ582.c \
	2> logs/f60_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f60_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f60_gcc.log || true)"
grep -v '^$' logs/f60_gcc.log | head -40 || true
ls -la vm/build/differ582
sha256sum vm/build/differ582 vm/differ582.c
