#!/bin/bash
# verify571_selftest.sh -- every mutation must turn verify571.py red; `noop`
# must leave it green.  A crash is not a caught mutation: the verifier has to
# run to completion and report bad>0.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
R1=logs/f49_rep1.log
R2=logs/f49_rep2.log
T=/tmp/v571_self
mkdir -p "$T"
pass=0; fail=0; n=0

base=$(python3 tools/verify571.py > "$T/base.out" 2>&1; echo $?)
if [ "$base" != 0 ]; then
	echo "SELFTEST: baseline is red -- nothing to test"
	cat "$T/base.out" | tail -20
	exit 1
fi
echo "baseline: checks=$(grep -o 'checks=[0-9]*' "$T/base.out")"

for m in lives imm post sport cntp drop prx l2 hwtype det frame noroute tap \
	 l2hex splat initrd mv hwhex noop; do
	n=$((n+1))
	python3 tools/f571_mutate.py "$m" "$R1" "$T/a.log" "$R2" "$T/b.log" \
		> "$T/mut.out" 2>&1 || { echo "MUTATE_FAIL $m"; fail=$((fail+1)); continue; }
	V571_REP1="$T/a.log" V571_REP2="$T/b.log" \
		python3 tools/verify571.py > "$T/out_$m.txt" 2>&1
	rc=$?
	if [ "$m" = noop ]; then
		if [ $rc -eq 0 ]; then
			pass=$((pass+1)); echo "ok   $m (stays green)"
		else
			fail=$((fail+1)); echo "FAIL $m (went red)"; tail -3 "$T/out_$m.txt"
		fi
	else
		if [ $rc -eq 0 ]; then
			fail=$((fail+1)); echo "FAIL $m (survived)"
		elif grep -q 'Traceback' "$T/out_$m.txt"; then
			fail=$((fail+1)); echo "FAIL $m (crash, not a catch)"
		else
			pass=$((pass+1)); echo "ok   $m ($(grep -o 'bad=[0-9]*' "$T/out_$m.txt" | head -1))"
		fi
	fi
done
echo "selftest: $pass/$n"
[ "$pass" = "$n" ] || exit 1
