#!/bin/bash
# verify552_selftest.sh -- does verify552.py actually go red when the log lies?
#
# A verifier that has never failed is not evidence.  Each mutation below breaks
# exactly one fact in a copy of the logs; the verifier must exit non-zero and
# the named check must be among the failures.  The baseline must be green.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
TMP=$(mktemp -d)
BASE="$TMP/base"
mkdir -p "$BASE"
for f in logs/f30_B_rep1.log logs/f30_B_rep2.log logs/f30_Q_rep1.log \
	 logs/f30_R_rep1.log logs/f30_G_rep1.log logs/f30_P_rep1.log; do
	[ -f "$f" ] && cp "$f" "$BASE/"
done
OFF_BAK="$TMP/f30_offsets.txt.bak"
cp research/f30_offsets.txt "$OFF_BAK"
restore() { cp "$OFF_BAK" research/f30_offsets.txt; rm -rf "$TMP"; }
trap restore EXIT

runs=0
fails=0

run_verifier() {  # run_verifier <dir>
	python3 tools/verify552.py --logs "$1" >"$TMP/out.txt" 2>&1
	echo $?
}

# 0. the baseline has to be green, or nothing below means anything
rc=$(run_verifier "$BASE")
if [ "$rc" != "0" ]; then
	echo "BASELINE RED -- selftest is meaningless"
	tail -20 "$TMP/out.txt"
	exit 1
fi
echo "baseline: green ($(grep -c '^' "$TMP/out.txt") lines)"

mutate() {  # mutate <name> <file> <sed-expr> <expected-check-substring>
	local name=$1 file=$2 expr=$3 want=$4
	local dir="$TMP/m_$name"
	rm -rf "$dir"; cp -r "$BASE" "$dir"
	sed -i "$expr" "$dir/$(basename "$file")"
	local rc
	rc=$(run_verifier "$dir")
	runs=$((runs + 1))
	if [ "$rc" = "0" ]; then
		echo "  MUTATION NOT CAUGHT: $name"
		fails=$((fails + 1))
		return
	fi
	if ! grep -q "$want" "$TMP/out.txt"; then
		echo "  caught $name, but not by '$want':"
		grep '^  ' "$TMP/out.txt" | head -3
		fails=$((fails + 1))
		return
	fi
	echo "  ok  $name -> red"
}

mutate counter_flip      logs/f30_B_rep1.log 's/^F552CNT 6\.1\.1|pkts=0/F552CNT 6.1.1|pkts=1/' B6.1.1.predicate
mutate counter_zero      logs/f30_B_rep1.log 's/^F552CNT 4\.1\.1|pkts=1/F552CNT 4.1.1|pkts=0/' B4.1.1.predicate
mutate frame_bit         logs/f30_B_rep1.log '0,/^F552 ip\.ip\.dscp|/{s/hex=45b800/hex=45b900/}' ip.ip.dscp.frame_is_mask_applied
# the logs end every line with CR (the console writes \r\n): an anchor on '$'
# is dead, which is the fifth time this project has paid for that lesson
mutate dead_frame_chg    logs/f30_B_rep1.log '/^F552 ip6\.ip6\.ecn|/ s/86dd60012345/86dd61012345/' ip6.ip6.ecn.refused_frame_identical
mutate nft_rc            logs/f30_B_rep1.log 's/^F552RC ip\.ip\.length 0/F552RC ip.ip.length 1/' ip.ip.length.nft_rc0
mutate nl_offset         logs/f30_B_rep1.log '0,/^F552NL ip6\.ip6\.ecn.*payload write/{s/@ network header + 1/@ network header + 0/}' ip6.ip6.ecn.geometry_covers_field
mutate kernel_version    logs/f30_B_rep1.log 's/^Linux version 7\.3\.4/Linux version 7.2.15/' B_rep1.kernel_version
mutate kernel_sha        logs/f30_B_rep1.log 's/^### sha256: d4b6420e/### sha256: d4b6420f/' B_rep1.kernel_hash
mutate consequence       logs/f30_B_rep1.log 's/^F552 C\.ip6\.ip6\.ecn|\(.*\)|deliv=0/F552 C.ip6.ip6.ecn|\1|deliv=1/' C.ip6.ip6.ecn.verdict_follows_store
mutate ll_counter        logs/f30_B_rep1.log 's/^\(F552V ll\.ll\.raw112 .*counter packets \)0/\11/' ll.ll.raw112.boundary_predicate
mutate arm_missing       logs/f30_B_rep1.log '/^F552 B4\.7\.1|/d' B4.7.1.present
mutate second_run        logs/f30_B_rep2.log 's/^F552CNT 4\.w12\.8|pkts=1/F552CNT 4.w12.8|pkts=0/' det.same_counters

# the constants themselves: a wrong offsetof must be refused
sed -i 's/^ip4\.ttl 8$/ip4.ttl 9/' research/f30_offsets.txt
rc=$(run_verifier "$BASE")
runs=$((runs + 1))
if [ "$rc" = "0" ] || ! grep -q 'offsets.ip4.ttl' "$TMP/out.txt"; then
	echo "  MUTATION NOT CAUGHT: offsets.ip4.ttl"
	fails=$((fails + 1))
else
	echo "  ok  offsets.ip4.ttl -> red"
fi
cp "$OFF_BAK" research/f30_offsets.txt

echo
echo "$runs mutations, $fails not caught"
[ "$fails" = "0" ] && echo "SELFTEST PASS" || echo "SELFTEST FAIL"
exit $([ "$fails" = "0" ] && echo 0 || echo 1)
