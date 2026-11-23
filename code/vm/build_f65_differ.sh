#!/bin/bash
# build_f65_differ.sh -- assemble and compile the turn-587 instrument (F65).
#
# differ587.c is GENERATED: differ586.c (the F64 instrument, itself generated
# from differ585) with its main() renamed to f586_entry, plus
# vm/differ587_add.c, which supplies the new main(), mode `flow` and mode `cap`.
#
# Two edits to the inherited code:
#   * f575_nfl_drain(): u8 b[40000] -> b[70000].  F65 logs a 61 262-byte
#     message (51 datagrams of 1200 bytes); a 40 000-byte receive buffer would
#     cut it, and a log that lies about its own size is the defect F40#2,
#     F50#5 and F64#2 were.
#   * the tap printer announces itself as F586: renamed to F587, so that one
#     log carries one instrument's name.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f586_entry(int argc, char **argv)/' \
	vm/differ586.c > vm/differ587.c
grep -q '^int f586_entry' vm/differ587.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ587.c && { echo "MAIN_STILL_THERE"; exit 1; }
python3 - <<'PY'
p = "/work/kernel-sec/vm/differ587.c"
s = open(p).read()
i = s.index("static void f575_nfl_drain(struct f575_pl *v)")
j = s.index("\n}", i)
blk = s[i:j]
assert "unsigned char b[40000];" in blk, "drain buffer not found"
s = s[:i] + blk.replace("unsigned char b[40000];", "unsigned char b[70000];") + s[j:]
assert s.count('printf("F586 TAP|') == 1, "tap prefix count"
assert s.count('printf("F586 TAPX|') == 1, "tapx prefix count"
s = s.replace('printf("F586 TAP|', 'printf("F587 TAP|')
s = s.replace('printf("F586 TAPX|', 'printf("F587 TAPX|')
open(p, "w").write(s)
print("patched_drain_buffer=1 tap_prefix=1")
PY
cat vm/differ587_add.c >> vm/differ587.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ587 vm/differ587.c \
	2> logs/f65_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f65_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f65_gcc.log || true)"
grep -v '^$' logs/f65_gcc.log | head -40 || true
ls -la vm/build/differ587
sha256sum vm/build/differ587 vm/differ587.c vm/differ587_add.c
