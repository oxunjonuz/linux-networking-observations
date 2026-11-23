#!/bin/bash
# verify553_selftest.sh -- does verify553.py have teeth?
#
# The baseline must be green, then each mutation must turn exactly ONE named
# check red.  A verifier that cannot be made to fail is not a verifier; this
# script exists because in this project a green run has twice been a broken
# instrument (F25's cpio parser, F30's keyed expectations).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
SRC=logs
TMP=$(mktemp -d)
pass=0
fail=0

run() { # run <dir> -> prints verdict line, sets RC
  F553_LOG="$1" python3 tools/verify553.py > "$TMP/out" 2>&1
  RC=$?
  tail -1 "$TMP/out" | sed 's/^/    /'
}

echo "== baseline (must be green)"
run "$SRC"
if [ $RC -eq 0 ]; then
  echo "  PASS baseline"; pass=$((pass+1))
else
  echo "  FAIL baseline is red"; fail=$((fail+1))
fi
base_out=$(cat "$TMP/out")

mutate() { # mutate <name> <file> <sed-expr> <expected substring of the failure>
  local name=$1 file=$2 expr=$3 want=$4
  local d="$TMP/$name"
  mkdir -p "$d"
  cp "$SRC"/f31_*.log "$d"/ 2>/dev/null
  sed -i "$expr" "$d/$file" || { echo "  FAIL sed $name"; fail=$((fail+1)); return; }
  if cmp -s "$SRC/$file" "$d/$file"; then
    echo "  FAIL mutation $name changed nothing (dead sed)"; fail=$((fail+1)); return
  fi
  run "$d"
  if [ $RC -ne 0 ] && grep -qF "$want" "$TMP/out"; then
    echo "  PASS $name"; pass=$((pass+1))
  else
    echo "  FAIL $name rc=$RC want='$want'"; sed 's/^/      /' "$TMP/out" | tail -5
    fail=$((fail+1))
  fi
}

echo "== mutations"
mutate m01_ingress_arm    f31_C_rep1.log \
  's/^\(F553 sb.raw42|.*|\)cnt=1|/\1cnt=0|/' \
  "the SAME arm the ip family refuses is applied"
mutate m02_arp_label_cell f31_C_rep1.log \
  's/^\(F553 br.raw8.0x0806|.*|\)nchg=3|/\1nchg=0|/' \
  "on the ARP-labelled frame the ttl store lands"
mutate m03_vlan_untag     f31_C_rep1.log \
  's/^\(F553 br.meta.tag.ip|.*|\)cnt=1|/\1cnt=0|/' \
  "the kernel's protocol field says ip, not 8021q"
mutate m04_family_skip    f31_Q_rep1.log \
  '/^F553 sb.raw42|SKIP=no-netdev-family/d' \
  "every netdev arm is marked SKIP"
mutate m05_family_line    f31_C_rep1.log \
  's/^F553 FAM|netdev=1|bridge=1|ip=1/F553 FAM|netdev=0|bridge=1|ip=1/' \
  "netdev/bridge/ip reachability"
mutate m06_ttl_byte       f31_B_rep1.log \
  's/22:3f>20/22:3f>21/' \
  "the ttl byte itself changed"
mutate m07_local_socket   f31_C_rep1.log \
  's/^\(F553L sd.nh22|.*|\)p6000=1|/\1p6000=0|/' \
  "a store at ingress moves the datagram to the socket on :6000"
mutate m08_kernel_hash    f31_R_rep1.log \
  's/^### sha256: [0-9a-f]\{64\}$/### sha256: 0000000000000000000000000000000000000000000000000000000000000000/' \
  "kernel sha256 in the log == the file"
mutate m09_determinism    f31_C_rep2.log \
  's/^\(F553 br.raw16.0x9100|.*|\)cnt=0|/\1cnt=1|/' \
  "two boots of the config kernel produce identical lines"
mutate m10_arp_overshoot  f31_C_rep1.log \
  's/^\(F553 br.arpov.pad|.*|\)nchg=16|/\1nchg=15|/' \
  "the 16-byte store at ARP offset 20 is applied"
mutate m11_verdict_cell   f31_C_rep1.log \
  's/^\(F553 br.drp.raw8.91|.*|\)cap=0|/\1cap=1|/' \
  "under policy drop a refused store swallows the counter"
mutate m12_refusal_uniform f31_M_rep1.log \
  's/^\(F553 sa.raw42|.*|\)cnt=0|/\1cnt=1|/' \
  "the refusal of sa.raw42 is identical"

echo
echo "== $pass passed, $fail failed"
rm -rf "$TMP"
[ "$fail" -eq 0 ]
