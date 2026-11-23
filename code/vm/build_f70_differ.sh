#!/bin/bash
# build_f70_differ.sh -- assemble and compile the turn-592 instrument (F70).
#
# differ592.c is GENERATED: differ591.c (the F69 instrument, which already
# carries f589_entry) with its main() renamed to f591_entry, plus
# vm/differ592_add.c, which supplies the new main() and mode `cond`:
# a kprobe on skb_condense() and a queue put exactly on the half-buffer
# boundary.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f591_entry(int argc, char **argv)/' \
	vm/differ591.c > vm/differ592.c
grep -q '^int f591_entry' vm/differ592.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ592_add.c >> vm/differ592.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ592.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ592 vm/differ592.c \
	2> logs/f70_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f70_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -c 'warning:' logs/f70_gcc.log || true)"
grep "error:" logs/f70_gcc.log | head -20 || true
ls -la vm/build/differ592
sha256sum vm/build/differ592 vm/differ592.c vm/differ592_add.c
