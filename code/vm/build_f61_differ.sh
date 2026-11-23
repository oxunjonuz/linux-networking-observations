#!/bin/bash
# build_f61_differ.sh -- assemble and compile the turn-583 instrument (F61).
#
# differ583.c is GENERATED: differ582.c (the F60 instrument, itself generated
# from differ581) with its main() renamed to f582_entry, plus
# vm/differ583_add.c, which supplies the new main() and mode `fwd`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f582_entry(int argc, char **argv)/' \
	vm/differ582.c > vm/differ583.c
grep -q '^int f582_entry' vm/differ583.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ583.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ583_add.c >> vm/differ583.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ583 vm/differ583.c \
	2> logs/f61_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f61_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f61_gcc.log || true)"
grep -v '^$' logs/f61_gcc.log | head -40 || true
ls -la vm/build/differ583
sha256sum vm/build/differ583 vm/differ583.c
