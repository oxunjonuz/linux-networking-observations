#!/bin/bash
# build_f62_differ.sh -- assemble and compile the turn-584 instrument (F62).
#
# differ584.c is GENERATED: differ583.c (the F61 instrument, itself generated
# from differ582) with its main() renamed to f583_entry, plus
# vm/differ584_add.c, which supplies the new main() and mode `gso`.
#
# Two edits to the inherited NFLOG parser, because F62 logs a 1248-byte
# message and the F61 parser kept 96 bytes and reported the TRUNCATED length
# as if it were the real one (a log that lies about its own size -- the
# F40#2/F50#5 class of defect):
#   struct f575_msg .p[96]  -> .p[1680]
#   M->plen = k             -> M->plen = pll      (true attribute length)
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f583_entry(int argc, char **argv)/' \
	vm/differ583.c > vm/differ584.c
grep -q '^int f583_entry' vm/differ584.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ584.c && { echo "MAIN_STILL_THERE"; exit 1; }
python3 - <<'PY'
import re
p = "/work/kernel-sec/vm/differ584.c"
s = open(p).read()
# the f575 parser only: its struct is the one named struct f575_msg
i = s.index("struct f575_msg {")
j = s.index("};", i)
blk = s[i:j]
assert "unsigned char p[96];" in blk, "f575 payload field not found"
s = s[:i] + blk.replace("unsigned char p[96];", "unsigned char p[1680];") + s[j:]
n = s.count("M->plen = k;")
assert n >= 1, "plen assignment not found"
s = s.replace("M->plen = k;", "M->plen = pll;")
open(p, "w").write(s)
print("patched_plen_sites=%d" % n)
PY
cat vm/differ584_add.c >> vm/differ584.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ584 vm/differ584.c \
	2> logs/f62_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f62_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f62_gcc.log || true)"
grep -v '^$' logs/f62_gcc.log | head -40 || true
ls -la vm/build/differ584
sha256sum vm/build/differ584 vm/differ584.c
