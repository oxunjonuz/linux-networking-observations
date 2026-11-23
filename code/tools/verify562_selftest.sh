#!/bin/bash
# verify562_selftest.sh -- the verifier must be red on every deliberate fault.
#
# Each mutation changes ONE field of a COPY of the two logs; the harness
# requires (a) the verifier exits non-zero and (b) the failing check is the
# one that field belongs to.  A crash is not a caught mutation.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
R1=logs/f40_rep1.log
R2=logs/f40_rep2.log
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

run() {  # run <rep1> <rep2>
	V562_REP1="$1" V562_REP2="$2" python3 tools/verify562.py 2>&1
}

fail=0
base=$(run "$R1" "$R2")
if echo "$base" | grep -q "^checks:.* failed: 0"; then
	echo "BASE ok: $(echo "$base" | head -1)"
else
	echo "BASE RED -- the verifier is not green on the real logs"
	echo "$base" | head -20
	exit 1
fi

MUTS=(
	"rd_p_live|read position on p gate=0 A (8,1)"
	"rd_q_nhoff|read position on q gate=1 B (8,1)"
	"rd_cv|candidate bytes are the frame's"
	"rd_wire|a read changes nothing"
	"pair_guard|guard verdict q gate=1 (8,1)"
	"pair_wrrd|wrrd: read after store q gate=1 (8,1)"
	"pair_bytes|rdwr bytes q gate=1 (16,4)"
	"ih_read|@ih read q gate=1 T (2,2)"
	"ih_dead|@ih read q gate=0 T (0,2)"
	"ih_bytes|@ih store bytes == the transport header q gate=1 (0,2)"
	"arp_guard|arp guard qa gate=1 (6,2)"
	"arp_bytes|qa: (6,2) writes ar_pro"
	"arp_read|arp read position qa gate=1 A (10,2)"
	"ksha|kernel sha in log"
	"isha|initrd sha in log"
	"done|F562 DONE in both"
	"ctl_ipin|ctl p: ipin"
	"det|rep1 == rep2 on every arm"
)

n=0
for m in "${MUTS[@]}"; do
	mut=${m%%|*}
	want=${m#*|}
	d="$TMP/$mut"
	python3 tools/f40_mutate.py "$R1" "$R2" "$d" "$mut" || {
		echo "MUTATOR FAIL $mut"; fail=1; continue; }
	out=$(run "$d/rep1.log" "$d/rep2.log")
	n=$((n + 1))
	if ! echo "$out" | grep -q "^checks:"; then
		echo "MUTATION $mut: verifier crashed -- not counted"; fail=1; continue
	fi
	if echo "$out" | grep -q "^checks:.* failed: 0"; then
		echo "MUTATION $mut: SURVIVED (verifier stayed green)"; fail=1; continue
	fi
	if echo "$out" | grep -q "FAIL .*$want"; then
		echo "MUTATION $mut: caught by '$want'"
	else
		echo "MUTATION $mut: red, but not on '$want':"
		echo "$out" | grep "FAIL" | head -3
		fail=1
	fi
done

echo "mutations=$n baseline=green failures=$fail"
[ "$fail" = 0 ] && echo "SELFTEST OK" || echo "SELFTEST FAIL"
exit "$fail"
