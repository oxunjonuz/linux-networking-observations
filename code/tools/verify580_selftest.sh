#!/bin/bash
# verify580_selftest.sh -- can verify580.py go red?
#
# Baseline: the two real boots must be green.  Then one single-field mutation
# at a time, applied to a copy of the log pair; every one must make the
# verifier exit non-zero *without* a traceback (a crash is not a caught
# mutation).  `noop` must stay green, and a missing log must be an error.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
TMP=tmp/sel580
rm -rf "$TMP"
mkdir -p "$TMP"
PASS=0
FAIL=0

run() {  # run <label> <expect: green|red>
	local label=$1 want=$2 out rc
	out=$(F58_LOGDIR="$TMP" python3 tools/verify580.py 2>&1)
	rc=$?
	if grep -q "Traceback" <<<"$out"; then
		echo "  CRASH  $label"
		FAIL=$((FAIL + 1))
		return
	fi
	if [ "$want" = green ] && [ $rc -eq 0 ]; then
		echo "  ok     $label (green, $(tail -1 <<<"$out"))"
		PASS=$((PASS + 1))
	elif [ "$want" = red ] && [ $rc -ne 0 ]; then
		echo "  ok     $label (red)"
		PASS=$((PASS + 1))
	else
		echo "  MISS   $label (want $want, rc=$rc)"
		FAIL=$((FAIL + 1))
	fi
}

cp logs/f58_rep1.log "$TMP/f58_rep1.log"
cp logs/f58_rep2.log "$TMP/f58_rep2.log"
run "baseline" green

MUTS="frame_byte arm_name arm_off arm_len arm_fid ch_stored ch_zero nl_lost \
nl_extra hw_byte p_byte pp_byte pindev pnl rc vlan l2lost u6n hdrerr noroutes \
udperr oth ukproto deliv snd pre"
for m in $MUTS; do
	python3 tools/f580_mutate.py logs/f58_rep1.log "$TMP/f58_rep1.log" "$m" \
		>/dev/null || { echo "  SKIP   $m (mutator failed)"; FAIL=$((FAIL+1)); continue; }
	run "$m" red
	python3 tools/f580_mutate.py logs/f58_rep1.log "$TMP/f58_rep1.log" noop
done

# --- one field changed in rep2 only: the determinism check must see it
cp logs/f58_rep1.log "$TMP/f58_rep1.log"
cp logs/f58_rep2.log "$TMP/f58_rep2.log"
python3 tools/f580_mutate.py logs/f58_rep2.log "$TMP/f58_rep2.log" \
	u6n >/dev/null || echo "  (mutator u6n on rep2 differs)"
run "det_u6n" red
cp logs/f58_rep2.log "$TMP/f58_rep2.log"

# --- noop must stay green
python3 tools/f580_mutate.py logs/f58_rep1.log "$TMP/f58_rep1.log" noop
run "noop" green

# --- a missing log must be an error, not a crash
rm -f "$TMP/f58_rep2.log"
run "missing-log" red

echo "=== PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ]
