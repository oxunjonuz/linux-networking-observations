#!/bin/bash
# build_f55_differ.sh -- assemble and compile the turn-577 instrument.
#
# differ577.c is GENERATED: differ576.c (the F54 instrument, itself generated)
# with its main() renamed to f576_entry, plus vm/differ577_add.c, which
# supplies the new main() and mode `pcp`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f576_entry(int argc, char **argv)/' \
	vm/differ576.c > vm/differ577.c
grep -q '^int f576_entry' vm/differ577.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ577.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ577_add.c >> vm/differ577.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ577 vm/differ577.c \
	2> logs/f55_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f55_gcc.log | head -80; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f55_gcc.log || true)"
grep -v '^$' logs/f55_gcc.log | head -60 || true
ls -la vm/build/differ577
sha256sum vm/build/differ577 vm/differ577.c
