#!/bin/bash
# verify572_selftest.sh -- prove that verify572.py can go red, one field at a time.
#
# Every mutation is a single field in logs/f50_rep1.log.  The baseline must be
# green; each mutation must make the verifier exit non-zero with at least one
# RED line; a crash (traceback) does NOT count as a caught mutation.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
V=tools/verify572.py
REP1=logs/f50_rep1.log
REP2=logs/f50_rep2.log
TMP=/tmp/v572_selftest
rm -rf "$TMP"; mkdir -p "$TMP"
PASS=0; FAIL=0
say() { printf '%s\n' "$*"; }

run_verifier() {  # run_verifier <rep1> -> prints "rc=<n> reds=<n> crash=<0|1>"
	local r1=$1 out rc reds crash
	out=$(V572_REP1="$r1" V572_REP2="$REP2" python3 "$V" 2>&1)
	rc=$?
	reds=$(printf '%s\n' "$out" | grep -c '^  RED: ')
	crash=0
	printf '%s\n' "$out" | grep -q 'Traceback (most recent call last)' && crash=1
	printf 'rc=%d reds=%d crash=%d' "$rc" "$reds" "$crash"
}

# ---------------- baseline
res=$(run_verifier "$REP1")
say "baseline: $res"
case "$res" in
"rc=0 reds=0 crash=0") PASS=$((PASS+1));;
*) say "  FAIL: baseline is not green"; FAIL=$((FAIL+1));;
esac

# ---------------- one field at a time
MUTS="w12_4_cnts rd_imm pre_dst_u6n pre_dst_fardst br_dst_other ctl_i6in
      dg2_m0 ref_ppp_rc ref_ppp_type pf6_cnts comp_cnts br_dst_br_farn
      nflog_n l2hdr frame_hop drop_arm"
for m in $MUTS; do
	out="$TMP/$m.log"
	if ! python3 tools/f572_mutate.py "$m" "$REP1" "$out" > "$TMP/$m.mut" 2>&1; then
		say "$m: MUTATION FAILED TO APPLY"
		cat "$TMP/$m.mut"
		FAIL=$((FAIL+1))
		continue
	fi
	res=$(run_verifier "$out")
	say "$m: $res"
	case "$res" in
	rc=0*)	say "  FAIL: the verifier did not notice"; FAIL=$((FAIL+1));;
	*crash=1*) say "  FAIL: crash, not a verdict"; FAIL=$((FAIL+1));;
	*reds=0*) say "  FAIL: non-zero exit but no RED line"; FAIL=$((FAIL+1));;
	*)	PASS=$((PASS+1));;
	esac
done

# ---------------- the no-op must stay green (the mutations are the variable)
python3 tools/f572_mutate.py noop "$REP1" "$TMP/noop.log" > /dev/null 2>&1
res=$(run_verifier "$TMP/noop.log")
say "noop: $res"
case "$res" in
"rc=0 reds=0 crash=0") PASS=$((PASS+1));;
*) say "  FAIL: a copy with no change went red"; FAIL=$((FAIL+1));;
esac

say "selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
