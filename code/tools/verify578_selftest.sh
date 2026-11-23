#!/bin/bash
# verify578_selftest.sh -- can verify578.py go red?
#
# Baseline: the two real boots must be green.  Then one single-field mutation
# at a time, each applied to a copy of the log pair; every one must make the
# verifier exit non-zero *without* a traceback (a crash is not a caught
# mutation).  `noop` must stay green.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
TMP=tmp/sel578
rm -rf "$TMP"
mkdir -p "$TMP"
PASS=0
FAIL=0

# the copy has to live in tools/ so that verify578.py's ROOT (two levels up
# from __file__) still resolves to the project root
VER=tools/_verify578_tmp.py
mkver() {  # mkver <dir>
	local d=$1
	[ "$d" = logs ] && d=$PWD/logs
	sed "s|LOGS = \['logs/f56_rep1.log', 'logs/f56_rep2.log'\]|LOGS = ['$d/f56_rep1.log', '$d/f56_rep2.log']|" \
		tools/verify578.py > "$VER"
}

run() {  # run <label> <expect: green|red>
	local label=$1 want=$2 out rc
	out=$(python3 "$VER" 2>&1)
	rc=$?
	if grep -q "Traceback" <<<"$out"; then
		echo "  CRASH  $label"
		FAIL=$((FAIL + 1))
		return
	fi
	if [ "$want" = green ] && [ $rc -eq 0 ]; then
		echo "  ok     $label (green)"
		PASS=$((PASS + 1))
	elif [ "$want" = red ] && [ $rc -ne 0 ]; then
		echo "  ok     $label (red: $(grep -c '^FAIL' <<<"$out") failures)"
		PASS=$((PASS + 1))
	else
		echo "  MISS   $label (want $want, rc=$rc)"
		FAIL=$((FAIL + 1))
	fi
}

# --- baseline: the real pair
mkver logs
run "baseline" green

MUTS="door counter tapbyte taplen readimm bfcount rxbytes vlanword outdev feat refused frame u6n vdev nest plen"
for m in $MUTS; do
	cp logs/f56_rep1.log "$TMP/f56_rep1.log"
	cp logs/f56_rep2.log "$TMP/f56_rep2.log"
	python3 tools/f578_mutate.py logs/f56_rep1.log "$TMP/f56_rep1.log" "$m" \
		>/dev/null || { echo "  SKIP   $m (mutator failed)"; FAIL=$((FAIL+1)); continue; }
	mkver "$TMP"
	run "$m" red
done

# --- noop must stay green
cp logs/f56_rep1.log "$TMP/f56_rep1.log"
cp logs/f56_rep2.log "$TMP/f56_rep2.log"
python3 tools/f578_mutate.py logs/f56_rep1.log "$TMP/f56_rep1.log" noop >/dev/null
mkver "$TMP"
run "noop" green

# --- a missing log must be an error, not a crash
rm -f "$TMP/f56_rep2.log"
mkver "$TMP"
run "missing-log" red

echo "=== PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ]
