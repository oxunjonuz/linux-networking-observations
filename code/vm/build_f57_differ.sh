#!/bin/bash
# build_f57_differ.sh -- assemble and compile the turn-579 instrument.
#
# differ579.c is GENERATED: differ578.c (the F56 instrument, itself generated
# from differ576) with its main() renamed to f578_entry, plus
# vm/differ579_add.c, which supplies the new main() and mode `priv`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f578_entry(int argc, char **argv)/' \
	vm/differ578.c > vm/differ579.c
grep -q '^int f578_entry' vm/differ579.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ579.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ579_add.c >> vm/differ579.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ579 vm/differ579.c \
	2> logs/f57_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f57_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f57_gcc.log || true)"
grep -v '^$' logs/f57_gcc.log | head -40 || true
ls -la vm/build/differ579
sha256sum vm/build/differ579 vm/differ579.c
