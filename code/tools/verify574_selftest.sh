#!/bin/bash
# verify574_selftest.sh -- does the F52 verifier notice a one-field lie?
#
# Baseline must be green; then every mutation of f574_mutate.py must redden the
# verifier without a traceback, and a missing log must exit 1 rather than crash.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
SRC=logs/f52_rep1.log
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if ! python3 tools/verify574.py "$SRC" > "$TMP/base.out" 2>&1; then
	echo "BASELINE_RED"
	tail -5 "$TMP/base.out"
	exit 1
fi
echo "baseline green: $(tail -1 "$TMP/base.out")"

n=0
ok=0
for m in $(python3 tools/f574_mutate.py --list); do
	n=$((n + 1))
	if ! python3 tools/f574_mutate.py "$SRC" "$TMP/$m.log" "$m" > "$TMP/$m.mut" 2>&1; then
		echo "MUTATE_FAIL $m: $(cat "$TMP/$m.mut")"
		continue
	fi
	python3 tools/verify574.py "$TMP/$m.log" > "$TMP/$m.out" 2>&1
	rc=$?
	if [ "$m" = "noop" ]; then
		if [ $rc -eq 0 ]; then
			echo "noop stays green"
			ok=$((ok + 1))
		else
			echo "NOOP_RED"
		fi
		continue
	fi
	if [ $rc -eq 1 ] && ! grep -q "Traceback" "$TMP/$m.out"; then
		ok=$((ok + 1))
	else
		echo "SURVIVED $m (rc=$rc)"
	fi
done
echo "caught $ok/$n"
[ $ok -eq $n ] || exit 1

python3 tools/verify574.py /nonexistent.log > "$TMP/miss.out" 2>&1
rc=$?
if [ $rc -eq 1 ] && ! grep -q "Traceback" "$TMP/miss.out"; then
	echo "missing log -> exit 1"
else
	echo "MISSING_LOG_CRASH rc=$rc"
	exit 1
fi
