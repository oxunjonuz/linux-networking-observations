#!/bin/bash
# build_f64_differ.sh -- assemble and compile the turn-586 instrument (F64).
#
# differ586.c is GENERATED: differ585.c (the F63 instrument, itself generated
# from differ584) with its main() renamed to f585_entry, plus
# vm/differ586_add.c, which supplies the new main() and mode `geom`.
#
# One edit to the inherited NFLOG parser: F64 logs a 32 790-byte message (the
# 64-datagram aggregate) and the inherited receive buffer is 16 384 bytes --
# recv() would return 16384 and the message would be silently cut in half,
# which is exactly the "a log that lies about its own size" defect F40#2 and
# F50#5 were.  The attribute lengths are the witness here, so the buffer must
# be able to hold one whole message:
#   f575_nfl_drain(): u8 b[16384] -> b[40000]
# And the inherited tap printer announces itself as F585: renamed to F586 so
# that one log carries one instrument's name.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p vm/build
sed 's/^int main(int argc, char \*\*argv)$/int f585_entry(int argc, char **argv)/' \
	vm/differ585.c > vm/differ586.c
grep -q '^int f585_entry' vm/differ586.c || { echo "RENAME_FAIL"; exit 1; }
grep -q '^int main(int argc, char \*\*argv)$' vm/differ586.c && { echo "MAIN_STILL_THERE"; exit 1; }
python3 - <<'PY'
p = "/work/kernel-sec/vm/differ586.c"
s = open(p).read()
i = s.index("static void f575_nfl_drain(struct f575_pl *v)")
j = s.index("\n}", i)
blk = s[i:j]
assert "unsigned char b[16384];" in blk, "drain buffer not found"
s = s[:i] + blk.replace("unsigned char b[16384];", "unsigned char b[40000];") + s[j:]
s = s.replace('printf("F585 TAP|', 'printf("F586 TAP|')
s = s.replace('printf("F585 TAPX|', 'printf("F586 TAPX|')
open(p, "w").write(s)
print("patched_drain_buffer=1 tap_prefix=1")
PY
cat vm/differ586_add.c >> vm/differ586.c
gcc -O2 -Wall -Wno-unused-function -static -o vm/build/differ586 vm/differ586.c \
	2> logs/f64_gcc.log || { echo "GCC_FAIL"; grep -v '^$' logs/f64_gcc.log | head -60; exit 1; }
echo "gcc_warnings=$(grep -vc '^$' logs/f64_gcc.log || true)"
grep -v '^$' logs/f64_gcc.log | head -40 || true
ls -la vm/build/differ586
sha256sum vm/build/differ586 vm/differ586.c vm/differ586_add.c
