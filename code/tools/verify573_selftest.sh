#!/bin/bash
# verify573_selftest.sh -- prove that verify573.py can go red, one field at a time.
#
# Every mutation is a single field in logs/f51_rep1.log.  The baseline must be
# green; each mutation must make the verifier exit non-zero with at least one
# MISMATCH line; a crash (traceback) does NOT count as a caught mutation.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
V=tools/verify573.py
REP1=logs/f51_rep1.log
REP2=logs/f51_rep2.log
TMP=/tmp/v573_selftest
rm -rf "$TMP"; mkdir -p "$TMP"
PASS=0; FAIL=0
say() { printf '%s\n' "$*"; }

run_verifier() {  # run_verifier <rep1> -> prints "rc=<n> bad=<n> crash=<0|1>"
	local r1=$1 out rc bad crash
	out=$(V573_REP1="$r1" V573_REP2="$REP2" python3 "$V" 2>&1)
	rc=$?
	bad=$(printf '%s\n' "$out" | grep -c '^  MISMATCH: ')
	crash=0
	printf '%s\n' "$out" | grep -q 'Traceback (most recent call last)' && crash=1
	printf 'rc=%d bad=%d crash=%d' "$rc" "$bad" "$crash"
}

# ---------------- baseline
res=$(run_verifier "$REP1")
say "baseline: $res"
case "$res" in
"rc=0 bad=0 crash=0") PASS=$((PASS+1));;
*) say "  FAIL: baseline is not green"; FAIL=$((FAIL+1));;
esac

# ---------------- one field at a time
MUTS="preS_y0_src in6D_y0_dst in6D_noT_cnts fwdS_cnts ctlA_i6in ctlA_disc
      preD_brf preD7_oth fwdS_m_payload brlH_m_payload tap_len in6D_u6n
      preS_sport rdA_cnts vlanC_in6 uniC_brrxp frameA_ethertype ctlA_nfl
      preS_st_zero brlH_br0_hoplimit"
for m in $MUTS; do
	cp "$REP1" "$TMP/m.log"
	if ! python3 tools/f573_mutate.py "$m" "$REP1" "$TMP/m.log" 2>"$TMP/err"; then
		say "$m: MUTATOR FAILED: $(head -1 "$TMP/err")"
		FAIL=$((FAIL+1))
		continue
	fi
	res=$(run_verifier "$TMP/m.log")
	rc=${res#rc=}; rc=${rc%% *}
	case "$res" in
	*"crash=1"*) say "$m: CRASH ($res)"; FAIL=$((FAIL+1));;
	"rc=0 bad=0 crash=0") say "$m: NOT CAUGHT ($res)"; FAIL=$((FAIL+1));;
	*) say "$m: caught ($res)"; PASS=$((PASS+1));;
	esac
done

# ---------------- a missing log must refuse, not crash
res=$(V573_REP1="$TMP/nope.log" V573_REP2="$REP2" python3 "$V" 2>&1)
rc=$?
if [ "$rc" -ne 0 ]; then PASS=$((PASS+1)); say "missing log: exits $rc (ok)";
else say "missing log: exits 0 (BAD)"; FAIL=$((FAIL+1)); fi

say "selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
