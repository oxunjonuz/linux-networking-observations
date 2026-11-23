#!/bin/bash
# verify570_selftest.sh -- the verifier must be green on the real logs and red
# on every single-field mutation of them.  A crash is not a caught mutation.
set -uo pipefail
cd /work/kernel-sec
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
base=logs/f48_rep1.log
python3 tools/verify570.py "$base" > "$T/base.out" 2>&1
rc=$?
grep -q 'bad=0' "$T/base.out" || { echo "BASELINE_FAIL"; tail -3 "$T/base.out"; exit 1; }
[ $rc -ne 0 ] && { echo "BASELINE_RC=$rc"; exit 1; }
echo "base OK $(grep '^checks=' "$T/base.out")"
pass=0; fail=0
for m in cnts cnts2 lives u6sport u6n kernel u6err drop tapbyte sbyte frame l4; do
	python3 tools/f570_mutate.py "$base" "$T/m.log" "$m" >/dev/null 2>&1 || { echo "MUT_$m NOT_APPLICABLE"; fail=$((fail+1)); continue; }
	python3 tools/verify570.py "$T/m.log" > "$T/m.out" 2>&1
	rc=$?
	if [ $rc -eq 0 ]; then
		echo "MUT_$m SURVIVED"
		fail=$((fail+1))
	elif [ $rc -ne 1 ]; then
		echo "MUT_$m CRASHED rc=$rc"
		fail=$((fail+1))
	elif ! grep -q '^checks=' "$T/m.out"; then
		echo "MUT_$m CRASHED (no summary)"
		fail=$((fail+1))
	else
		echo "MUT_$m caught $(grep -c BAD "$T/m.out")"
		pass=$((pass+1))
	fi
done
echo "selftest pass=$pass fail=$fail"
[ $fail -eq 0 ] || exit 1
