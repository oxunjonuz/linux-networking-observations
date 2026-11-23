#!/bin/bash
# build_f29_differ.sh -- differ551.c = differ544.c (F22 harness, which already
# has the `W <hexframe>` peer command and the tunnel frame builders) + the
# turn-551 F29 battery in vm/differ551_add.c.
#
# differ544 is the base on purpose: F29 needs exactly what F22 built -- send
# these exact bytes, return the forwarded datagram -- and nothing of the F27/F28
# payload-store harness that differ550 carries (the store builder is 40 lines
# and is written again here, next to the arms that use it).
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
cp vm/differ544.c vm/differ551.c
python3 - <<'PY'
p = '/work/kernel-sec/vm/differ551.c'
add = open('/work/kernel-sec/vm/differ551_add.c').read()
s = open(p).read()

a = "static void run_f22(void);\n"
assert s.count(a) == 1, "run_f22 decl anchor"
s = s.replace(a, a + "static void run_f551(void);\n")

a = '\tif (!strcmp(mode, "f22"))\n\t\trun_f22();\n'
assert s.count(a) == 1, "f22 dispatch anchor"
s = s.replace(a, a + '\tif (!strcmp(mode, "f551"))\n\t\trun_f551();\n')

s = s + "\n" + add
open(p, 'w').write(s)
print("differ551.c assembled:", len(s), "bytes")
PY
gcc -O2 -static -Wall -o vm/build/differ551 vm/differ551.c 2>logs/f29_build_differ.log || true
if grep -q " error" logs/f29_build_differ.log; then echo "COMPILE ERROR"; head -80 logs/f29_build_differ.log; exit 1; fi
echo "--- warnings (non-unused) ---"
grep "warning" logs/f29_build_differ.log | grep -v "unused" | head -10 || true
grep -c "warning" logs/f29_build_differ.log || true
file vm/build/differ551 | cut -c1-120
sha256sum vm/build/differ551 vm/differ551.c vm/differ551_add.c
