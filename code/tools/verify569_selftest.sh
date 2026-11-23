#!/bin/bash
# verify569_selftest.sh -- every check of verify569.py must be able to go red.
#
# The baseline must be green, and each single-field mutation of a copy of the
# logs (tools/f569_mutate.py) must turn it red.  A crash is not a caught
# mutation: the verifier has to exit non-zero *and* print a check failure.
set -uo pipefail
ROOT=/work/kernel-sec
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
pass=0; fail=0

run() { F569_LOGS="$T/a.log:$T/b.log" python3 "$ROOT/tools/verify569.py" > "$T/out" 2>&1; echo $?; }

check() {  # check <name> <expected rc>
	local name=$1 want=$2 rc
	rc=$(run)
	if [ "$rc" = "$want" ] && ! grep -q "Traceback" "$T/out"; then
		pass=$((pass+1)); echo "  PASS $name (rc=$rc, $(tail -1 "$T/out"))"
	else
		fail=$((fail+1)); echo "  FAIL $name (want rc=$want, got $rc)"
		grep -m3 "!!\|Traceback" "$T/out" | sed 's/^/      /'
	fi
}

mut() {  # mut <name>
	local name=$1
	cp -f "$ROOT/logs/f47_rep1.log" "$T/a.log"
	if ! python3 "$ROOT/tools/f569_mutate.py" "$name" "$T/a.log" > "$T/mut" 2>&1; then
		fail=$((fail+1)); echo "  FAIL $name (mutator: $(cat "$T/mut"))"
		return
	fi
	check "$name" 1
	cp -f "$ROOT/logs/f47_rep1.log" "$T/a.log"
}

cp -f "$ROOT/logs/f47_rep1.log" "$T/a.log"
cp -f "$ROOT/logs/f47_rep2.log" "$T/b.log"
check baseline 0

for m in lives_up cntp0 nodeliver hopwire droparm ksha isha isocnt hopdecrement csum; do
	mut "$m"
done

rm -f "$T/b.log"
check missing-second-boot 1
cp -f "$ROOT/logs/f47_rep2.log" "$T/b.log"

echo "SELFTEST $pass passed, $fail failed"
[ "$fail" = 0 ]
