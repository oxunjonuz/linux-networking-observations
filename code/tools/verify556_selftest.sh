#!/bin/bash
# verify556_selftest.sh -- does verify556.py actually go red?
#
# Twelve mutations, one at a time, each on a COPY of the turn's log.  The
# mutated copy is used as BOTH boots, so the determinism comparison is green
# and each mutation can only be caught by the check it attacks.  The baseline
# (the real log against itself) must be green first, or no score is reported.
#
# usage: bash tools/verify556_selftest.sh
set -uo pipefail
cd /work/kernel-sec
BASE=logs/f33_T_rep1.log
MUT=logs/f33_mut
PASS=0; FAIL=0

expect() {  # expect <name> <substring-that-must-appear-in-a-failure>
  local name=$1 want=$2 out rc
  out=$(python3 tools/verify556.py "mut_$name" "mut_$name" --dev 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then
    echo "MUT $name: NOT CAUGHT (verifier stayed green)"
    FAIL=$((FAIL+1)); return
  fi
  if echo "$out" | grep -q "$want"; then
    echo "MUT $name: caught by $want"
    PASS=$((PASS+1))
  else
    echo "MUT $name: caught, but not by $want:"
    echo "$out" | grep "^FAIL" | head -3
    FAIL=$((FAIL+1))
  fi
}

edit() {  # edit <name> <python-expression-on-s>
  python3 - "$1" "$2" <<'EOF'
import re, sys
name, expr = sys.argv[1], sys.argv[2]
src = open("logs/f33_T_rep1.log", errors="replace").read()
out = eval(expr, {"re": re, "s": src})
assert out != src, "mutation changed nothing"
open("logs/f33_mut_%s.log" % name, "w").write(out)
EOF
}

echo "=== baseline (must be green) ==="
if python3 tools/verify556.py T_rep1 T_rep1 --dev >/tmp/f33base 2>&1; then
  echo "baseline green: $(tail -1 /tmp/f33base)"
  PASS=$((PASS+1))
else
  echo "BASELINE RED -- mutations prove nothing:"
  grep "^FAIL" /tmp/f33base | head -5
  exit 1
fi

edit cell_live_dead 's.replace("F556 R|env=ip4|arm=g0_2|off=0|len=2|kind=0|rc=0|cnt=1|cnt0=0", "F556 R|env=ip4|arm=g0_2|off=0|len=2|kind=0|rc=0|cnt=0|cnt0=0")'
expect cell_live_dead "cell.ip4.0_2.cnt"

edit cell_dead_live 's.replace("F556 R|env=ip4|arm=g2_1|off=2|len=1|kind=0|rc=0|cnt=0|cnt0=0", "F556 R|env=ip4|arm=g2_1|off=2|len=1|kind=0|rc=0|cnt=1|cnt0=0")'
expect cell_dead_live "cell.ip4.2_1.cnt"

edit ingress_cell 's.replace("F556 R|env=nd|arm=g12_4|off=12|len=4|kind=0|rc=0|cnt=1|cnt0=0", "F556 R|env=nd|arm=g12_4|off=12|len=4|kind=0|rc=0|cnt=0|cnt0=0")'
expect ingress_cell "cell.nd.12_4.cnt"

edit egress_cell 's.replace("F556 R|env=eg4|arm=g8_4|off=8|len=4|kind=0|rc=0|cnt=0|cnt0=0", "F556 R|env=eg4|arm=g8_4|off=8|len=4|kind=0|rc=0|cnt=1|cnt0=0")'
expect egress_cell "cell.eg4.8_4.cnt"

edit arp_cell 's.replace("F556 R|env=arp|arm=g6_4|off=6|len=4|kind=2|rc=0|cnt=0|cnt0=0", "F556 R|env=arp|arm=g6_4|off=6|len=4|kind=2|rc=0|cnt=1|cnt0=0")'
expect arp_cell "cell.arp.6_4.cnt"

edit ll_boundary 's.replace("F556 R|env=ll4|arm=g12_4|off=12|len=4|kind=0|rc=0|cnt=0|cnt0=0", "F556 R|env=ll4|arm=g12_4|off=12|len=4|kind=0|rc=0|cnt=1|cnt0=0")'
expect ll_boundary "cell.ll4.12_4.cnt"

edit bytes_nibble 're.sub(r"(F556 R\|env=ip4\|arm=g10_2\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|hex=)([0-9a-f]{4})", lambda m: m.group(1) + ("0" if m.group(2)[0] != "0" else "1") + m.group(2)[1:], s)'
expect bytes_nibble "cell.ip4.10_2.bytes"

edit install_rc 's.replace("F556 R|env=ip6|arm=x8_16|off=8|len=16|kind=1|rc=0", "F556 R|env=ip6|arm=x8_16|off=8|len=16|kind=1|rc=-22")'
expect install_rc "cell.ip6.8_16.rc0"

edit control_cnt 's.replace("F556 CTL|env=ip4|kind=0|rc=0|cnt=1|cnt0=0", "F556 CTL|env=ip4|kind=0|rc=0|cnt=3|cnt0=0")'
expect control_cnt "grid.ip4.control"

edit e_arm 's.replace("F556 R|env=eb|arm=br_6_2_arp|off=6|len=2|kind=2|rc=0|cnt=1|cnt0=0", "F556 R|env=eb|arm=br_6_2_arp|off=6|len=2|kind=2|rc=0|cnt=0|cnt0=0")'
expect e_arm "E.bridge_switch_by_label"

edit no_log 's.replace("F556 R|env=brA|arm=g10_1|off=10|len=1|kind=2|rc=0|cnt=1|cnt0=0|nfl=46", "F556 R|env=brA|arm=g10_1|off=10|len=1|kind=2|rc=0|cnt=1|cnt0=0|nfl=0")'
expect no_log "cell.brA.10_1.nfl"

edit kernel_sha 's.replace("### sha256: ", "### sha256: 00", 1)'
expect kernel_sha "kernel_sha"

echo "----"
echo "verify556_selftest: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
