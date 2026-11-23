#!/bin/bash
# verify581_selftest.sh -- does verify581.py ever go red?
#
# Baseline green, then one single-field mutation of the log per round: each
# must turn the verifier red WITHOUT a traceback.  `noop` must stay green, a
# missing log must exit 1, an empty log must exit 1 rather than crash.
set -uo pipefail
cd /work/kernel-sec
LOG=${1:-logs/f59_rep1.log}
MUT=tools/f581_mutate.py
V=tools/verify581.py
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
fail=0
n=0

if ! python3 "$V" "$LOG" "$LOG" > "$TMP/base.out" 2>&1; then
	echo "BASELINE_RED"; head -5 "$TMP/base.out"; exit 1
fi
echo "baseline green: $(head -1 "$TMP/base.out")"

for m in $(python3 "$MUT" --list); do
	n=$((n + 1))
	if ! python3 "$MUT" "$LOG" "$m" "$TMP/$m.log" 2>"$TMP/$m.err"; then
		echo "MUTATION_NOT_APPLIED $m: $(head -1 "$TMP/$m.err")"
		fail=1
		continue
	fi
	out=$(python3 "$V" "$TMP/$m.log" "$TMP/$m.log" 2>&1)
	rc=$?
	if echo "$out" | grep -q "Traceback"; then
		echo "CRASH $m"
		fail=1
	elif [ "$m" = "noop" ]; then
		if [ $rc -ne 0 ]; then echo "NOOP_RED"; fail=1; else echo "noop green"; fi
	elif [ $rc -eq 0 ]; then
		echo "SURVIVED $m"
		fail=1
	else
		echo "killed $m: $(echo "$out" | sed -n '2p' | cut -c1-110)"
	fi
done

if python3 "$V" "$TMP/does_not_exist.log" "$TMP/does_not_exist.log" >/dev/null 2>&1; then
	echo "MISSING_LOG_GREEN"; fail=1
else
	[ $? -eq 1 ] || { echo "MISSING_LOG_NOT_EXIT_1"; fail=1; }
fi
: > "$TMP/empty.log"
out=$(python3 "$V" "$TMP/empty.log" "$TMP/empty.log" 2>&1)
[ $? -eq 1 ] && ! echo "$out" | grep -q Traceback || { echo "EMPTY_LOG_BAD"; fail=1; }

echo "rounds=$n fail=$fail"
[ $fail -eq 0 ] && echo "SELFTEST OK"
exit $fail
