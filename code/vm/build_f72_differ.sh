#!/bin/bash
# build_f72_differ.sh -- assemble and compile the turn-594 instrument (F72).
#
# differ594.c is GENERATED: differ593.c (the F71 instrument, which already
# carries f591_entry and f592_entry) with its main() renamed to f593_entry,
# plus vm/differ594_add.c, which supplies the new main() and modes `zc`/`cl`:
# a SO_ZEROCOPY/MSG_ZEROCOPY sender through both GRO doors, and a packet
# socket inside the receiver that keeps its frames or a `ret 0` filter that
# keeps none.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f593_entry(int argc, char **argv)/' \
	vm/differ593.c > vm/differ594.c
grep -q '^int f593_entry' vm/differ594.c || { echo "RENAME_FAIL"; exit 1; }
cat vm/differ594_add.c >> vm/differ594.c
grep -c '^int main(int argc, char \*\*argv)$' vm/differ594.c | grep -qx 1 || { echo "MAIN_COUNT"; exit 1; }
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ594 vm/differ594.c \
	2> logs/f72_gcc.log || { echo "GCC_FAIL"; grep "error:" logs/f72_gcc.log | head -40; exit 1; }
echo "gcc_warnings=$(grep -c 'warning:' logs/f72_gcc.log || true)"
grep "error:" logs/f72_gcc.log | head -20 || true
ls -la vm/build/differ594
sha256sum vm/build/differ594 vm/differ594.c vm/differ594_add.c
