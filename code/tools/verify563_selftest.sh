#!/bin/bash
# verify563_selftest.sh -- the verifier must be red on every deliberate fault.
#
# Each mutation changes ONE field of a COPY of the two logs; the harness
# requires (a) the verifier exits non-zero and (b) the failing check is the
# one that field belongs to.  A crash is not a caught mutation.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
R1=logs/f41_rep1.log
R2=logs/f41_rep2.log
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

run() {  # run <rep1> <rep2>
	V563_REP1="$1" V563_REP2="$2" python3 tools/verify563.py 2>&1
}

fail=0
base=$(run "$R1" "$R2")
if echo "$base" | grep -q "^checks=.* failed=0"; then
	echo "BASE ok: $(echo "$base" | head -1)"
else
	echo "BASE RED -- the verifier is not green on the real logs"
	echo "$base" | head -20
	exit 1
fi

MUTS=(
	"rd_cv|cand A is cap["
	"rd_live|off=8 len=1 live"
	"st_live|s4_2 live"
	"st_bytes|s4_2 bytes"
	"pair_wrrd|wrrd_8.b live"
	"pair_bytes|wr_16.d bytes"
	"ih_live|rdT_0_2 live"
	"ih_bytes|store lands at 42"
	"ppp_rxn|pppd id_small recv length"
	"ppp_rx|pppd ctl recv bytes"
	"arp_arc|br_q0_hln reaches NF_ARP_IN"
	"arp_reply|br_pa_opbad reply"
	"arp_ent|entry holds the sha"
	"arp_bytes|br_q0_pro store bytes"
	"det|rep1 == rep2"
	"ksha|kernel sha in the log == the file"
	"mode|MODE_EXIT 0"
)

n=0
for m in "${MUTS[@]}"; do
	mut=${m%%|*}
	want=${m#*|}
	d="$TMP/$mut"
	python3 tools/f41_mutate.py "$R1" "$R2" "$d" "$mut" >/dev/null || {
		echo "MUTATOR FAIL $mut"; fail=1; continue; }
	out=$(run "$d/rep1.log" "$d/rep2.log")
	n=$((n + 1))
	if ! echo "$out" | grep -q "^checks="; then
		echo "MUTATION $mut: verifier crashed -- not counted"; fail=1; continue
	fi
	if echo "$out" | grep -q "failed=0"; then
		echo "MUTATION $mut: SURVIVED ($want)"; fail=1; continue
	fi
	if ! echo "$out" | grep -qF "$want"; then
		echo "MUTATION $mut: reddened the wrong check (wanted: $want)"
		echo "$out" | grep -A3 "first 25 failures" | head -5
		fail=1; continue
	fi
	echo "mutant $mut: caught by '$want'"
done
echo "### SELFTEST mutations=$n fail=$fail"
[ "$fail" = 0 ] && echo "### SELFTEST OK" || echo "### SELFTEST FAIL"
exit "$fail"
