#!/bin/bash
# build_f54_differ.sh -- assemble and compile the turn-576 instrument.
#
# differ576.c is GENERATED: differ575.c (the F53 instrument, itself generated
# from the F52 one) with its main() renamed to f575_entry, plus
# vm/differ576_add.c, which supplies the new main() and modes `warn` and `xf`.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f575_entry(int argc, char **argv)/' \
	vm/differ575.c > vm/differ576.c
grep -q '^int f575_entry' vm/differ576.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ576.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ576_add.c >> vm/differ576.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ576 vm/differ576.c \
	2> logs/f54_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f54_gcc.log | head -80; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f54_gcc.log || true)"
grep -v '^$' logs/f54_gcc.log | head -60 || true
ls -la vm/build/differ576
sha256sum vm/build/differ576 vm/differ576.c
