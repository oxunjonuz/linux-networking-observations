#!/bin/bash
# build_f52_differ.sh -- assemble and compile the turn-574 instrument.
#
# differ574.c is GENERATED: differ573.c (the F51 instrument, itself generated
# from the F50 one) with its main() renamed to f573_entry, plus
# vm/differ574_add.c, which supplies the new main() and mode `tag`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f573_entry(int argc, char **argv)/' \
	vm/differ573.c > vm/differ574.c
grep -q '^int f573_entry' vm/differ574.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ574.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ574_add.c >> vm/differ574.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ574 vm/differ574.c \
	2> logs/f52_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f52_gcc.log | head -80; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f52_gcc.log || true)"
grep -v '^$' logs/f52_gcc.log | head -60 || true
ls -la vm/build/differ574
sha256sum vm/build/differ574 vm/differ574.c
