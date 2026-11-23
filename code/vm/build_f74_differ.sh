#!/bin/bash
# build_f74_differ.sh -- assemble and compile the turn-596 instrument (F74).
#
# differ596.c is GENERATED: differ595.c (the F73 instrument, which already
# carries f591_entry..f594_entry) with its main() renamed to f595_entry, plus
# vm/differ596_add.c, which supplies the new main() and the modes `q` (the
# queue's bill for 64 zerocopy datagrams) and `h` (where `end` comes from).
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f595_entry(int argc, char **argv)/' \
	vm/differ595.c > vm/differ596.c
grep -q '^int f595_entry' vm/differ596.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ596_add.c >> vm/differ596.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ596.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ596 vm/differ596.c \
	2> logs/f74_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f74_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -c 'warning:' logs/f74_gcc.log || true)"
grep "error:" logs/f74_gcc.log | head -20 || true
ls -la vm/build/differ596
sha256sum vm/build/differ596 vm/differ596.c vm/differ596_add.c
