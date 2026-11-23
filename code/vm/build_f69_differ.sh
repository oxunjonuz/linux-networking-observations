#!/bin/bash
# build_f69_differ.sh -- assemble and compile the turn-591 instrument (F69).
#
# differ591.c is GENERATED: differ589.c (the F68 instrument) with its main()
# renamed to f589_entry, plus vm/differ591_add.c, which supplies the new main()
# and modes `cap` (the fraglist byte cap with equal payloads) and `price`
# (the truesize ladder A(k) = (2k-1)*s of a GRO aggregate).
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f589_entry(int argc, char **argv)/' \
	vm/differ589.c > vm/differ591.c
grep -q '^int f589_entry' vm/differ591.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ591_add.c >> vm/differ591.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ591.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ591 vm/differ591.c \
	2> logs/f69_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f69_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -c 'warning:' logs/f69_gcc.log || true)"
grep "error:" logs/f69_gcc.log | head -20 || true
ls -la vm/build/differ591
sha256sum vm/build/differ591 vm/differ591.c vm/differ591_add.c
