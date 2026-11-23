#!/bin/bash
# build_f47_differ.sh -- assemble and compile the turn-569 instrument.
#
# differ569.c is GENERATED: differ568.c (the F46 instrument) with its main()
# renamed to f568_main, plus vm/differ569_add.c.  Every helper under the new
# code is the one that produced F31..F46.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
sed 's/^int main(int argc, char \*\*argv)$/int f568_main(int argc, char **argv)/' \
	vm/differ568.c > vm/differ569.c
grep -q '^int f568_main' vm/differ569.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ569.c && { echo "MAIN_STILL_THERE"; exit 1; }
cat vm/differ569_add.c >> vm/differ569.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ569 vm/differ569.c \
	2> logs/f47_gcc.log || { echo "GCC_FAIL"; tail -60 logs/f47_gcc.log; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f47_gcc.log || true)"
grep -v '^$' logs/f47_gcc.log | head -40 || true
ls -la vm/build/differ569
sha256sum vm/build/differ569 vm/differ569.c
