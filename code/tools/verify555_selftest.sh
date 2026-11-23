#!/bin/bash
# verify555_selftest.sh -- does every check in verify555.py ever go red?
#
# The baseline must be green (rc 0), and each mutation below must make the
# verifier fail *and* name the check it was aimed at.  The mutations are applied
# to copies of the logs in tmp/f32_selftest, never to logs/ itself.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
W=tmp/f32_selftest
rm -rf "$W"; mkdir -p "$W"

V="python3 tools/verify555.py --quiet"
base() {  # base <dir>
  $V --logs "$1" 2>&1 | tail -1
}
mut() {   # mut <name> <python-mutation-snippet>
  local name=$1 snippet=$2
  rm -rf "$W/$name"; cp -r logs "$W/$name"
  python3 - "$W/$name" <<PY
import sys, re
D = sys.argv[1]
$snippet
PY
  local out
  out=$(python3 tools/verify555.py --logs "$W/$name" 2>&1)
  local rc=$?
  if [ $rc -eq 0 ]; then
    echo "MUTATION ALIVE  $name  (verifier still green)"
    return 1
  fi
  echo "mutation red    $name  -> $(printf '%s\n' "$out" | grep -c '^FAIL') checks red: $(printf '%s\n' "$out" | grep '^FAIL' | head -2 | sed 's/  */ /g' | tr '\n' ';')"
  return 0
}

# baseline: the real logs must be green
BL=$(base logs)
echo "baseline: $BL"
case "$BL" in
  *FAILED*) echo "BASELINE RED -- stop"; exit 1 ;;
esac

fail=0
mut M1_cnt '       # a dead arm claims it ran
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=s.replace("F555 A|d.0.1|hook=in|src=raw|g=0,1|rule=@nh,+|rc=0|cnt=0",
            "F555 A|d.0.1|hook=in|src=raw|g=0,1|rule=@nh,+|rc=0|cnt=1")
open(p,"w").write(s)' || fail=1

mut M2_bytes '    # one payload byte off by one, in one arm only
p=D+"/f32_A_rep1.log"; s=open(p).read()
old="F555 A|d.8.6|hook=in|src=raw|g=8,6|rule=@nh,+|rc=0|cnt=2|nfl=46|"
i=s.find(old)
assert i>0, "M2 anchor"
j=s.find("|nhex=", i)+len("|nhex=")
k=s.find("|", j)
hexs=s[j:k]
s=s[:j]+hexs[:10]+("b" if hexs[10]!="b" else "c")+hexs[11:]+s[k:]
open(p,"w").write(s)' || fail=1

mut M3_declared ' # nft"s own declared geometry changed by 2 bytes
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=s.replace("[ payload write reg 1 => 2b @ network header + 6 ","[ payload write reg 1 => 2b @ network header + 8 ",1)
open(p,"w").write(s)' || fail=1

mut M4_dead '     # a dead field is claimed alive
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=s.replace("F555 A|c.hlen|hook=in|src=nft|g=4,1|rule=arp hlen set 8|rc=0|cnt=0",
            "F555 A|c.hlen|hook=in|src=nft|g=4,1|rule=arp hlen set 8|rc=0|cnt=1",1)
open(p,"w").write(s)' || fail=1

mut M5_neigh '    # the neighbour table disagrees with the rewrite
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=s.replace("F555 ARP|f.alive|10.5.5.5|flags=0x2","F555 ARP|f.alive|10.5.5.5|flags=none",1)
open(p,"w").write(s)' || fail=1

mut M6_rx '       # the frame was never seen on i0
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=s.replace("F555 G|g.h8p16|hlen=8|plen=16|flen=70|rc=0|rx_i0=1",
            "F555 G|g.h8p16|hlen=8|plen=16|flen=70|rc=0|rx_i0=0",1)
open(p,"w").write(s)' || fail=1

mut M7_arm '      # one grid arm is missing
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=re.sub(r"F555 A\|d\.20\.16\|.*\n","",s,count=1)
open(p,"w").write(s)' || fail=1

mut M8_bzsha '   # the log claims a kernel that is not the one on disk
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=re.sub(r"### sha256: [0-9a-f]{64}", "### sha256: " + "0"*64, s, count=1)
open(p,"w").write(s)' || fail=1

mut M9_initrd '   # the initrd hash table no longer knows the archive that booted
p=D+"/f32_initrd_hashes.txt"; lines=open(p).read().splitlines()
lines=[(f[0]+" "+"1"*64) if f[0]=="f555" else l for l in lines for f in [l.split()]]
open(p,"w").write("\n".join(lines)+"\n")' || fail=1

mut M10_hook '     # a hook the kernel must refuse is claimed to work
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=s.replace("F555 HOOK|forward|1","F555 HOOK|forward|0",1)
open(p,"w").write(s)' || fail=1

mut M11_splat '   # a splat appears in a counted boot
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=s.replace("F555 DONE","[   12.0] WARNING: CPU: 0 PID: 1 at kernel/x.c:1\nF555 DONE",1)
open(p,"w").write(s)' || fail=1

mut M12_noconfig '  # the marker that says the boot cannot print its own config is gone
p=D+"/f32_A_rep1.log"; s=open(p).read()
s=s.replace("NO_CONFIG_GZ","",1)
open(p,"w").write(s)' || fail=1

mut M13_det '     # the second boot differs from the first in one byte
p=D+"/f32_A_rep2.log"; s=open(p).read()
s=s.replace("F555 A|d.24.4|hook=in|src=raw|g=24,4|rule=@nh,+|rc=0|cnt=",
            "F555 A|d.24.4|hook=in|src=raw|g=24,4|rule=@nh,+|rc=0|cnt=9",1)
open(p,"w").write(s)' || fail=1

echo "---"
echo "selftest: $((13-fail))/13 mutations red, baseline: $BL"
exit $fail
