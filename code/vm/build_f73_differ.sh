#!/bin/bash
# build_f73_differ.sh -- assemble and compile the turn-595 instrument (F73).
#
# differ595.c is GENERATED: differ594.c (the F72 instrument, which already
# carries f591_entry/f592_entry/f593_entry) with its main() renamed to
# f594_entry, plus vm/differ595_add.c, which supplies the new main() and the
# modes `chg` (where the zerocopy page charge is) and `cln` (who calls
# skb_clone, by caller address).
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f594_entry(int argc, char **argv)/' \
	vm/differ594.c > vm/differ595.c
grep -q '^int f594_entry' vm/differ595.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ595_add.c >> vm/differ595.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ595.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ595 vm/differ595.c \
	2> logs/f73_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f73_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -c 'warning:' logs/f73_gcc.log || true)"
grep "error:" logs/f73_gcc.log | head -20 || true
ls -la vm/build/differ595
sha256sum vm/build/differ595 vm/differ595.c vm/differ595_add.c
