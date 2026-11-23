#!/bin/bash
# build_f68_differ.sh -- assemble and compile the turn-590 instrument (F68).
#
# differ590.c is GENERATED: differ589.c (the F67 instrument) with its main()
# renamed to f589_entry, plus vm/differ590_add.c, which supplies the new main()
# and modes `cap4` and `cond4` -- the IPv4 twin of the GRO byte cap and of the
# receive-queue budget.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f589_entry(int argc, char **argv)/' \
	vm/differ589.c > vm/differ590.c
grep -q '^int f589_entry' vm/differ590.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ590_add.c >> vm/differ590.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ590.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ590 vm/differ590.c \
	2> logs/f68_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f68_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -c 'warning:' logs/f68_gcc.log || true)"
grep "error:" logs/f68_gcc.log | head -20 || true
ls -la vm/build/differ590
sha256sum vm/build/differ590 vm/differ590.c vm/differ590_add.c
