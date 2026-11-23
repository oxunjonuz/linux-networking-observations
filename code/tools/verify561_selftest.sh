#!/bin/bash
# verify561_selftest.sh -- the verifier must be red on every deliberate fault.
#
# Each mutation changes ONE field of a COPY of the two logs; the harness
# requires (a) the verifier exits non-zero and (b) the failing check is the
# one that field belongs to.  A crash is not a caught mutation.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
R1=logs/f39_rep1.log
R2=logs/f39_rep2.log
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

run() {  # run <rep1> <rep2>  -> prints "checks=.. failed=.." and the FAIL lines
	V561_REP1="$1" V561_REP2="$2" python3 tools/verify561.py 2>&1
}

fail=0
base=$(run "$R1" "$R2")
if echo "$base" | grep -q "checks=.* failed=0"; then
	echo "BASE ok: $(echo "$base" | head -1)"
else
	echo "BASE RED -- the verifier is not green on the real logs"
	echo "$base" | head -20
	exit 1
fi

# mutation: expected substring in a FAIL line
MUTS=(
	"ll_p_live|ll p g8_1: verdict"
	"ll_p_wire|ll p g8_1: wire bytes"
	"ll_q_16_2|ll q g16_2: verdict"
	"meta_q|meta q reports"
	"unlock_qmeta|unlock q.meta g8_1: verdict"
	"xmit_b88|xmit B_01.p88a8: wire bytes"
	"far_q|far q: the far tap"
	"far_wire|far w: the far tap"
	"ll_ipin|ll p: control ipin"
	"ndin_ctl_ipin|ndin q: control ipin"
	"ndin_double|ndin q g0_2: live"
	"ksha|kernel sha"
	"isha|initrd sha in log"
	"done|F561 DONE"
)

n=0
for m in "${MUTS[@]}"; do
	mut=${m%%|*}
	want=${m#*|}
	d="$TMP/$mut"
	python3 tools/f39_mutate.py "$R1" "$R2" "$d" "$mut" || { echo "MUTATOR FAIL $mut"; fail=1; continue; }
	out=$(run "$d/rep1.log" "$d/rep2.log")
	n=$((n + 1))
	if ! echo "$out" | grep -q "^checks="; then
		echo "MUTATION $mut: verifier crashed -- not counted"; fail=1; continue
	fi
	if echo "$out" | grep -q "^checks=.* failed=0"; then
		echo "MUTATION $mut: SURVIVED (verifier stayed green)"; fail=1; continue
	fi
	if echo "$out" | grep -q "FAIL .*$want"; then
		echo "MUTATION $mut: caught by '$want'"
	else
		echo "MUTATION $mut: red, but not on '$want':"
		echo "$out" | grep "^FAIL" | head -3
		fail=1
	fi
done

echo "mutations=$n baseline=green failures=$fail"
[ "$fail" = 0 ] && echo "SELFTEST OK" || echo "SELFTEST FAIL"
exit "$fail"
