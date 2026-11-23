#!/bin/bash
# verify579_selftest.sh -- can verify579.py go red?
#
# Baseline: the two real boots must be green.  Then one single-field mutation
# at a time, applied to a copy of the log pair; every one must make the
# verifier exit non-zero *without* a traceback (a crash is not a caught
# mutation).  `noop` must stay green, and a missing log must be an error.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
TMP=tmp/sel579
rm -rf "$TMP"
mkdir -p "$TMP"
PASS=0
FAIL=0

# the copy lives in tools/ so verify579.py's ROOT resolves to the project root
VER=tools/_verify579_tmp.py
mkver() {  # mkver <dir>
	local d=$1
	[ "$d" = logs ] && d=$PWD/logs
	sed "s|LOGS = \['logs/f57_rep1.log', 'logs/f57_rep2.log'\]|LOGS = ['$d/f57_rep1.log', '$d/f57_rep2.log']|" \
		tools/verify579.py > "$VER"
	grep -q "LOGS = \['$d/f57_rep1.log'" "$VER" || {
		echo "  SED-FAIL (the LOGS line moved)"; exit 2; }
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
		echo "  ok     $label (red: $(grep -c 'BAD:' <<<"$out") failures)"
		PASS=$((PASS + 1))
	else
		echo "  MISS   $label (want $want, rc=$rc)"
		FAIL=$((FAIL + 1))
	fi
}

# --- baseline: the real pair
mkver logs
run "baseline" green

MUTS="cap_root cap_uid cap_ns_store cap_ns_rd cap_fx cap_fx2 cap_fore maps move \
unshare vdev frame wire bypass nh_evasion nh_deliv l4_evasion u6n ukproto snd rc door"
for m in $MUTS; do
	cp logs/f57_rep1.log "$TMP/f57_rep1.log"
	cp logs/f57_rep2.log "$TMP/f57_rep2.log"
	python3 tools/f579_mutate.py logs/f57_rep1.log "$TMP/f57_rep1.log" "$m" \
		>/dev/null || { echo "  SKIP   $m (mutator failed)"; FAIL=$((FAIL+1)); continue; }
	mkver "$TMP"
	run "$m" red
done

# --- noop must stay green
cp logs/f57_rep1.log "$TMP/f57_rep1.log"
cp logs/f57_rep2.log "$TMP/f57_rep2.log"
python3 tools/f579_mutate.py logs/f57_rep1.log "$TMP/f57_rep1.log" noop >/dev/null
mkver "$TMP"
run "noop" green

# --- a missing log must be an error, not a crash
rm -f "$TMP/f57_rep2.log"
mkver "$TMP"
run "missing-log" red

rm -f "$VER"
echo "=== PASS=$PASS FAIL=$FAIL"
[ $FAIL -eq 0 ]
