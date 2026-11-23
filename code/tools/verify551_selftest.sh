#!/bin/bash
# verify551_selftest.sh -- does verify551.py actually go red?
#
# A verifier that has never failed has not been tested.  This script runs it on
# the real logs (baseline must be green), then on copies where one byte of one
# log has been changed, and requires that (a) the run fails and (b) the failure
# names the check that owns that line.  Each mutation is applied to a scratch
# copy only; the real logs are never touched.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
V="python3 tools/verify551.py"
BASE=$(mktemp -d)
PASS=0
FAIL=0

run_mut() {  # run_mut <name> <expected check substring> <python mutation code>
  local name=$1 want=$2 code=$3
  local dir
  dir=$(mktemp -d)
  cp logs/f29_*_rep1.log "$dir"/ 2>/dev/null
  cp logs/f29_B_rep2.log "$dir"/ 2>/dev/null
  MUTDIR="$dir" python3 - "$code" <<'PY'
import os, sys, glob
code = sys.argv[1]
d = os.environ["MUTDIR"]
files = sorted(glob.glob(os.path.join(d, "f29_*_rep*.log")))
ns = {"files": files, "open": open, "d": d}
exec(code, ns)
PY
  if [ $? -ne 0 ]; then
    echo "MUTATION-SETUP-FAIL $name"
    FAIL=$((FAIL+1)); rm -rf "$dir"; return
  fi
  local out
  out=$(F29_LOGDIR="$dir" $V 2>&1)
  local rc=$?
  if [ $rc -eq 0 ]; then
    echo "NOT-CAUGHT $name (verifier still green)"
    FAIL=$((FAIL+1))
  elif echo "$out" | grep -q -- "$want"; then
    echo "ok  $name -> $(echo "$out" | grep -m1 '^FAILED: ') "
    PASS=$((PASS+1))
  else
    echo "WRONG-CHECK $name (failed, but not on '$want')"
    echo "$out" | grep '^FAILED: ' | head -3
    FAIL=$((FAIL+1))
  fi
  rm -rf "$dir"
}

echo "== baseline (must be green) =="
if $V > /tmp/f29_base.out 2>&1; then
  echo "ok  baseline $(tail -2 /tmp/f29_base.out | head -1)"
  PASS=$((PASS+1))
else
  echo "BASELINE-RED"; tail -5 /tmp/f29_base.out; FAIL=$((FAIL+1))
fi

# 1. an inner store that did move: say it did not (cap -> 0 on 7.3.4)
run_mut "A.ih.vx.do6 delivered->not" "a.B.f29_B_rep1.log.ih.vx.do6.cap" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read()
t = t.replace("F551 A.ih.vx.do6|kind=1|rule=@ih,432,8 set 0x60|nftrc=0|il3=64|il4=84|sent=1|cap=1",
              "F551 A.ih.vx.do6|kind=1|rule=@ih,432,8 set 0x60|nftrc=0|il3=64|il4=84|sent=1|cap=0")
open(p,"w").write(t)
'
# 2. the doff byte in the captured frame put back to 0x50
run_mut "A.ih.vx.do6 doff byte reverted" "a.B.f29_B_rep1.log.ih.vx.do6" '
p = [f for f in files if "B_rep1" in f][0]
lines = open(p).read().split("\n")
for i,l in enumerate(lines):
    if l.startswith("F551 A.ih.vx.do6|"):
        pre, tail = l.rsplit("|cap=",1)
        cap = bytearray(bytes.fromhex(tail))
        cap[82] = 0x50
        lines[i] = pre + "|cap=" + cap.hex()
open(p,"w").write("\n".join(lines))
'
# 3. a transport arm that was refused: claim it was delivered
run_mut "B.t.12.1 delivered->1" "b.B.f29_B_rep1.log.t.12.1.delivered" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read()
t = t.replace("F551 B.t.12.1|kind=0|base=2|off=12|len=1|csum=1,16|covers12=1|sent=1|cap=0",
              "F551 B.t.12.1|kind=0|base=2|off=12|len=1|csum=1,16|covers12=1|sent=1|cap=1")
i = t.index("F551 B.t.12.1|")
j = t.index("|cap=\n", i)
ctl = [l for l in t.split("\n") if l.startswith("F551 B.ctl.kind0|")][0]
t = t[:j] + "|cap=" + ctl.rsplit("|cap=",1)[1] + t[j+len("|cap="):]
open(p,"w").write(t)
'
# 4. an odd inner store whose checksum is invalid: claim it valid (7.3.4)
run_mut "B.i.55.1 itcsum->1" "b.B.f29_B_rep1.log.i.55.1" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read()
t = t.replace("F551 B.i.55.1|kind=1|base=3|off=55|len=1|csum=1,58|covers12=-1|sent=1|cap=1|iplen=94|nchg=2|chg=97:18>02,100:6b>81|itcsum=0",
              "F551 B.i.55.1|kind=1|base=3|off=55|len=1|csum=1,58|covers12=-1|sent=1|cap=1|iplen=94|nchg=2|chg=97:18>02,100:6b>81|itcsum=1")
open(p,"w").write(t)
'
# 5. the parity-fixed kernel: claim its odd store is still invalid
run_mut "D.odd.55 on P548 valid->0" "d.P.f29_P_rep1.log.odd.55" '
p = [f for f in files if "P_rep1" in f][0]
t = open(p).read()
t = t.replace("F551 D.odd.55|kind=1|base=3|off=55|len=1|csum=1,58|covers12=-1|sent=1|cap=1|iplen=94|nchg=2|chg=97:18>02,101:1b>31|itcsum=1",
              "F551 D.odd.55|kind=1|base=3|off=55|len=1|csum=1,58|covers12=-1|sent=1|cap=1|iplen=94|nchg=2|chg=97:18>02,100:6b>eb|itcsum=0")
open(p,"w").write(t)
'
# 6. the verdict counter: a refused store reported as counted
run_mut "C.th.do6 counter 0->1" "c.B.f29_B_rep1.log.th.do6" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read()
t = t.replace("F551 C.th.do6|kind=0|rule=@th,96,8 set 0x60|nftrc=0|sent=1|cap=0|iplen=0|nchg=-1|chg=-|itcsum=-1|counter_before=0|counter_after=0",
              "F551 C.th.do6|kind=0|rule=@th,96,8 set 0x60|nftrc=0|sent=1|cap=0|iplen=0|nchg=-1|chg=-|itcsum=-1|counter_before=0|counter_after=1")
open(p,"w").write(t)
'
# 7. nft said the rule failed: flip the exit code
run_mut "A.ih.gn.do6 nftrc->1" "a.B.f29_B_rep1.log.ih.gn.do6.nftrc" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read()
t = t.replace("F551 A.ih.gn.do6|kind=2|rule=@ih,496,8 set 0x60|nftrc=0",
              "F551 A.ih.gn.do6|kind=2|rule=@ih,496,8 set 0x60|nftrc=1")
open(p,"w").write(t)
'
# 8. nft'"'"'s own message: claim the store was on the transport base
run_mut "NL base inner->transport" "nl.B.f29_B_rep1.log.ih.vx.do6.base" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read()
t = t.replace("F551NL ih.vx.do6   [ payload write reg 1 => 2b @ inner header + 54",
              "F551NL ih.vx.do6   [ payload write reg 1 => 2b @ transport header + 54")
open(p,"w").write(t)
'
# 9. the kernel hash: name a different kernel
run_mut "provenance kernel sha" "prov.B.f29_B_rep1.log.kernel_sha" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read()
i = t.index("### sha256: ")
t = t[:i] + "### sha256: " + "0"*64 + t[i+11+64:]
open(p,"w").write(t)
'
# 10. the boot log must say which kernel booted
run_mut "boot version" "prov.B.f29_B_rep1.log.boot_version" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read()
t = t.replace("Linux version 7.3.4", "Linux version 7.3.5")
open(p,"w").write(t)
'
# 11. a truncated run must not look complete
run_mut "no F551 DONE" "prov.B.f29_B_rep1.log.done" '
p = [f for f in files if "B_rep1" in f][0]
t = open(p).read().replace("F551 DONE", "F551 FINISHED")
open(p,"w").write(t)
'
# 12. the outer UDP checksum in a captured frame, made invalid
run_mut "A.ih.udp.do6 oucsum broken" "a.B.f29_B_rep1.log.ih.udp.do6.oucsum" '
p = [f for f in files if "B_rep1" in f][0]
lines = open(p).read().split("\n")
for i,l in enumerate(lines):
    if l.startswith("F551 A.ih.udp.do6|"):
        pre, tail = l.rsplit("|cap=",1)
        cap = bytearray(bytes.fromhex(tail))
        cap[26] ^= 0xff
        lines[i] = pre + "|cap=" + cap.hex()
open(p,"w").write("\n".join(lines))
'

echo
echo "== $PASS passed, $FAIL failed =="
rm -rf "$BASE"
[ $FAIL -eq 0 ]
