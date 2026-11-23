#!/bin/bash
# verify583_selftest.sh -- can verify583.py ever go red?
#
# baseline: green (exit 0).  every single-clause mutation: red (exit 1) and
# NOT a crash (a traceback means the verifier died, not that it noticed).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
pass=0; fail=0
say() { printf '%-26s %s\n' "$1" "$2"; }

out=$(python3 tools/verify583.py 2>&1); rc=$?
if [ $rc -eq 0 ]; then say baseline "green: $(echo "$out" | head -1)"; pass=$((pass+1));
else say baseline "RED (expected green): $out"; fail=$((fail+1)); fi

for m in $(python3 - <<'PY'
import sys
sys.path.insert(0, 'tools')
import f583_mutate as f
print(' '.join(f.M.keys()))
PY
); do
	p=$(python3 tools/f583_mutate.py "$m") || { say "$m" "could not build"; fail=$((fail+1)); continue; }
	out=$(timeout 900 python3 "$p" 2>&1); rc=$?
	if echo "$out" | grep -q "Traceback"; then
		say "$m" "CRASH (traceback) -- not a real catch"; fail=$((fail+1))
	elif [ "$m" = noop ] && [ $rc -eq 0 ]; then
		say "$m" "green, as a control must be"; pass=$((pass+1))
	elif [ $rc -ne 0 ]; then
		say "$m" "red: $(echo "$out" | head -1)"; pass=$((pass+1))
	else
		say "$m" "STILL GREEN -- hole in the verifier"; fail=$((fail+1))
	fi
	rm -f "$p"
done
# a missing log must be red without a crash
mv logs/f61_rep2.log /tmp/f61_rep2.log.keep
out=$(python3 tools/verify583.py 2>&1); rc=$?
if echo "$out" | grep -q Traceback; then say missing-log "CRASH"; fail=$((fail+1));
elif [ $rc -ne 0 ]; then say missing-log "red, no crash"; pass=$((pass+1));
else say missing-log "GREEN without a log"; fail=$((fail+1)); fi
mv /tmp/f61_rep2.log.keep logs/f61_rep2.log
echo "selftest: $pass ok, $fail bad"
[ $fail -eq 0 ]
