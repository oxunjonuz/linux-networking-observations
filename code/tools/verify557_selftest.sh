#!/bin/bash
# verify557_selftest.sh -- does every check in verify557.py ever go red?
#
# Baseline must be green; each mutation must make the verifier fail and name
# the check it was aimed at.  Mutations are applied to COPIES of logs/ under
# tmp/f35_selftest, never to logs/ itself.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
W=tmp/f35_selftest
rm -rf "$W"; mkdir -p "$W"

base() { python3 tools/verify557.py --logs "$1" 2>&1 | tail -1; }

mut() {   # mut <name> <python snippet>
	local name=$1 snippet=$2
	rm -rf "$W/$name"; cp -r logs "$W/$name"
	python3 - "$W/$name" <<PY
import sys, re
D = sys.argv[1]
$snippet
PY
	local out rc
	out=$(python3 tools/verify557.py --logs "$W/$name" 2>&1); rc=$?
	if [ $rc -eq 0 ]; then
		echo "MUTATION ALIVE  $name  (verifier still green)"
		return 1
	fi
	echo "mutation red    $name  -> $(printf '%s\n' "$out" | grep -c '^FAIL') red: $(printf '%s\n' "$out" | grep '^FAIL' | head -2 | sed 's/  */ /g' | tr '\n' ';')"
	return 0
}

BL=$(base logs)
echo "baseline: $BL"
case "$BL" in
	*"0 fail"*) ;;
	*) echo "BASELINE RED -- stop"; exit 1 ;;
esac

fail=0
# a dead cell claims it ran, in the plain envelope
mut M1_plain_cell_alive 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F557 R|env=p4|arm=g14_1|off=14|len=1|kind=0|fast=1|rc=0|acks=1|cnt=0",
            "F557 R|env=p4|arm=g14_1|off=14|len=1|kind=0|fast=1|rc=0|acks=1|cnt=1",1)
open(p,"w").write(s)' || fail=1

# the VLAN envelope loses the cell the whole finding is about
mut M2_vlan_16_2_dies 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F557 R|env=vB|arm=g16_2|off=16|len=2|kind=1|fast=1|rc=0|acks=1|cnt=1",
            "F557 R|env=vB|arm=g16_2|off=16|len=2|kind=1|fast=1|rc=0|acks=1|cnt=0",1)
open(p,"w").write(s)' || fail=1

# the slow F33 helper and the fast helper disagree about one cell
mut M3_slow_fast_differ 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F556 R|env=p4s|arm=g6_1|off=6|len=1|kind=0|rc=0|cnt=1",
            "F556 R|env=p4s|arm=g6_1|off=6|len=1|kind=0|rc=0|cnt=0",1)
open(p,"w").write(s)' || fail=1

# a control arm stops seeing its frame
mut M4_control_lost 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F557 CTL|env=vB|kind=1|fast=1|rc=0|acks=1|cnt=1",
            "F557 CTL|env=vB|kind=1|fast=1|rc=0|acks=1|cnt=0",1)
open(p,"w").write(s)' || fail=1

# the verdict arm that must pass on a plain frame now dies
mut M5_verdict_plain 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F557 R|env=bp|arm=b12_1|off=12|len=1|kind=0|fast=1|rc=0|acks=1|cnt=1",
            "F557 R|env=bp|arm=b12_1|off=12|len=1|kind=0|fast=1|rc=0|acks=1|cnt=0",1)
open(p,"w").write(s)' || fail=1

# the verdict arm that must die on a tagged frame now passes
mut M6_verdict_vlan 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F557 R|env=bv|arm=b12_1|off=12|len=1|kind=1|fast=1|rc=0|acks=1|cnt=0",
            "F557 R|env=bv|arm=b12_1|off=12|len=1|kind=1|fast=1|rc=0|acks=1|cnt=1",1)
open(p,"w").write(s)' || fail=1

# the L3 tunnel stops being uniformly dead
mut M7_ipip_alive 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F557 R|env=ipip|arm=g0_1|off=0|len=1|kind=2|fast=1|rc=0|acks=1|cnt=0",
            "F557 R|env=ipip|arm=g0_1|off=0|len=1|kind=2|fast=1|rc=0|acks=1|cnt=1",1)
open(p,"w").write(s)' || fail=1

# provenance: the recorded kernel hash no longer matches the image
mut M8_kernel_sha 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=re.sub(r"(### sha256: )([0-9a-f]{64})", lambda m: m.group(1)+"0"*64, s, count=1)
open(p,"w").write(s)' || fail=1

# provenance: the version line
mut M9_version 'p=D+"/f35_T_rep2.log"; s=open(p).read()
s=s.replace("Linux version 7.3.4","Linux version 7.2.15",1)
open(p,"w").write(s)' || fail=1

# a splat inside the run
mut M10_splat 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("=== DMESG_TAIL ===",
            "[  41.000000] BUG: KASAN: slab-out-of-bounds in nft_do_chain\n=== DMESG_TAIL ===",1)
open(p,"w").write(s)' || fail=1

# the ip-family VLAN control starts claiming the frame arrived
mut M11_vv_control 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F557 CTL|env=vv|kind=1|fast=1|rc=0|acks=1|cnt=0",
            "F557 CTL|env=vv|kind=1|fast=1|rc=0|acks=1|cnt=1",1)
open(p,"w").write(s)' || fail=1

# one vxlan cell different from plain ethernet
mut M12_vxlan_cell 'p=D+"/f35_T_rep1.log"; s=open(p).read()
s=s.replace("F557 R|env=vxlan|arm=g10_1|off=10|len=1|kind=3|fast=1|rc=0|acks=1|cnt=1",
            "F557 R|env=vxlan|arm=g10_1|off=10|len=1|kind=3|fast=1|rc=0|acks=1|cnt=0",1)
open(p,"w").write(s)' || fail=1

# cross-boot determinism: the grid boot disagrees with the full boot
mut M13_cross_boot 'p=D+"/f35_T_grid.log"; s=open(p).read()
s=s.replace("F557 R|env=pB|arm=g2_1|off=2|len=1|kind=0|fast=1|rc=0|acks=1|cnt=1",
            "F557 R|env=pB|arm=g2_1|off=2|len=1|kind=0|fast=1|rc=0|acks=1|cnt=0",1)
open(p,"w").write(s)' || fail=1

# the F33 reference envelope (turn 556) no longer reproduces
mut M14_f33_regress 'p=D+"/f33_T_rep1.log"; s=open(p).read()
s=s.replace("F556 R|env=ll4|arm=g0_4|off=0|len=4|kind=0|rc=0|cnt=1",
            "F556 R|env=ll4|arm=g0_4|off=0|len=4|kind=0|rc=0|cnt=0",1)
open(p,"w").write(s)' || fail=1

echo "### selftest done, fail=$fail"
exit $fail
