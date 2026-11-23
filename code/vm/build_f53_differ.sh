#!/bin/bash
# build_f53_differ.sh -- assemble and compile the turn-575 instrument.
#
# differ575.c is GENERATED: differ574.c (the F52 instrument, itself generated
# from the F51 one) with its main() renamed to f574_entry, plus
# vm/differ575_add.c, which supplies the new main() and mode `reorder`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f574_entry(int argc, char **argv)/' \
	vm/differ574.c > vm/differ575.c
grep -q '^int f574_entry' vm/differ575.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ575.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ575_add.c >> vm/differ575.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ575 vm/differ575.c \
	2> logs/f53_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f53_gcc.log | head -80; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f53_gcc.log || true)"
grep -v '^$' logs/f53_gcc.log | head -60 || true
ls -la vm/build/differ575
sha256sum vm/build/differ575 vm/differ575.c
