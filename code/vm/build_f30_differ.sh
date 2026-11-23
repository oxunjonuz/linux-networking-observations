#!/bin/bash
# build_f30_differ.sh -- differ552.c = differ550.c (the F27/F28 harness: the
# two-netns veth pair, the hand-built IPv4 probe with capture, the payload
# store builder, the nft driver) + the turn-552 F30 battery in
# vm/differ552_add.c.
#
# F30 needs three things differ550 does not have: an IPv6 route and a
# permanent neighbour on the near side (so a hand-built IPv6 frame is
# forwarded instead of delivered), a peer command 'V' that sends that frame
# and reads it back, and nft-table builders that take a family argument.
# Every patch below is asserted: a silent miss would leave a binary that runs
# F28's battery and reports nothing about F30.
set -euo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
cp vm/differ550.c vm/differ552.c
python3 - <<'PY'
p = '/work/kernel-sec/vm/differ552.c'
add = open('/work/kernel-sec/vm/differ552_add.c').read()
s = open(p).read()

a = "static void run_f550(void);\n"
assert s.count(a) == 1, "run_f550 decl anchor"
s = s.replace(a, a + "static void run_f552(void);\n")

a = '\tif (!strcmp(mode, "f550"))\n\t\trun_f550();\n'
assert s.count(a) == 1, "f550 dispatch anchor"
s = s.replace(a, a + '\tif (!strcmp(mode, "f552"))\n\t\trun_f552();\n')

a = "static int f539_peer_loop(int rfd, int wfd)\n{\n"
assert s.count(a) == 1, "peer loop anchor"
s = s.replace(a, "static int f552_peer_v6(int plen, unsigned char *out, int *flen,\n"
		 "\t\t\tint *nsent, int *ncap);\n" + a)

a = "\t\t} else if (line[0] == 'N' && line[1] == '2') {\n"
assert s.count(a) == 1, "peer N2 anchor"
v = ("\t\t} else if (line[0] == 'V') {\n"
     "\t\t\tint plen = 16, nsent = 0, ncap = 0, flen = 0, rc, j, k = 0;\n"
     "\t\t\tunsigned char fr[512];\n"
     "\t\t\tchar vrep[1200];\n"
     "\n"
     "\t\t\tsscanf(line + 1, \"%d\", &plen);\n"
     "\t\t\tmemset(fr, 0, sizeof(fr));\n"
     "\t\t\trc = f552_peer_v6(plen, fr, &flen, &nsent, &ncap);\n"
     "\t\t\tif (rc < 0)\n"
     "\t\t\t\tk = snprintf(vrep, sizeof(vrep), \"D %d 0 0\\n\", rc);\n"
     "\t\t\telse\n"
     "\t\t\t\tk = snprintf(vrep, sizeof(vrep), \"D %d %d %d \",\n"
     "\t\t\t\t\t     nsent, ncap, flen);\n"
     "\t\t\tfor (j = 0; rc >= 0 && j < flen && (size_t)k + 4 < sizeof(vrep); j++)\n"
     "\t\t\t\tk += snprintf(vrep + k, sizeof(vrep) - (size_t)k, \"%02x\", fr[j]);\n"
     "\t\t\tif (rc >= 0)\n"
     "\t\t\t\tsnprintf(vrep + k, sizeof(vrep) - (size_t)k, \"\\n\");\n"
     "\t\t\tf539_write_all(wfd, vrep, (int)strlen(vrep));\n")
s = s.replace(a, v + a)

s = s + "\n" + add
open(p, 'w').write(s)
print("differ552.c assembled:", len(s), "bytes")
PY
gcc -O2 -static -Wall -o vm/build/differ552 vm/differ552.c 2>logs/f30_build_differ.log || true
if grep -q " error" logs/f30_build_differ.log; then echo "COMPILE ERROR"; head -60 logs/f30_build_differ.log; exit 1; fi
echo "--- warnings (non-unused) ---"
grep "warning" logs/f30_build_differ.log | grep -v "unused" | head -10 || true
grep -c "warning" logs/f30_build_differ.log || true
file vm/build/differ552 | cut -c1-120
sha256sum vm/build/differ552 vm/differ552.c vm/differ552_add.c
