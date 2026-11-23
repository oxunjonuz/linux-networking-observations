#!/bin/bash
# verify559_selftest.sh -- the verifier must be able to go red.
#
# Baseline: the real logs must pass.  Then each mutation of ONE field in a copy
# of the logs must make verify559.py fail with a FAIL line -- and a mutation that
# merely crashes the verifier (Traceback) is NOT counted as caught.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
pass=0
fail=0
T=$(mktemp -d /tmp/v559.XXXXXX)
trap 'rm -rf "$T"' EXIT

baseline() {
	rm -rf "$T"
	mkdir -p "$T"
	cp logs/f37_rep1.log "$T/f37_rep1.log"
	cp logs/f37_rep2.log "$T/f37_rep2.log"
}

run() {
	python3 tools/verify559.py --logs rep1,rep2 --logdir "$T" > "$T/out.txt" 2>&1
	echo $?
}

baseline
rc=$(run)
if [ "$rc" = "0" ] && grep -q "failed=0" "$T/out.txt"; then
	echo "BASELINE ok ($(grep -o 'checks=[0-9]*' "$T/out.txt"))"
	pass=$((pass+1))
else
	echo "BASELINE RED rc=$rc"
	tail -5 "$T/out.txt"
	fail=$((fail+1))
fi

mut() {  # mut <rule> <log> <name>
	local rule=$1 file=$2 name=$3
	baseline
	if ! python3 tools/f37_mutate.py "$T/f37_$file.log" "$rule" > "$T/mut.txt" 2>&1; then
		echo "MUT-BROKEN $name: $(tail -1 "$T/mut.txt")"
		fail=$((fail+1))
		return
	fi
	local rc
	rc=$(run)
	if [ "$rc" != "0" ] && ! grep -q "Traceback" "$T/out.txt" && grep -q "^FAIL" "$T/out.txt"; then
		echo "MUT-CAUGHT $name -> $(grep -m1 '^FAIL' "$T/out.txt" | cut -c1-110)"
		pass=$((pass+1))
	else
		echo "MUT-SURVIVED $name rc=$rc"
		tail -4 "$T/out.txt"
		fail=$((fail+1))
	fi
}

mut wire_byte            rep1 wire-byte
mut wire_far_byte        rep1 far-byte
mut wire_truncated       rep1 wire-truncated
mut grid_live_to_dead    rep1 grid-live-to-dead
mut grid_dead_to_live    rep1 grid-dead-to-live
mut grid_doff_lost       rep1 doff-guard-lost
mut grid_wrong_offset    rep1 grid-wrong-offset
mut set_rc               rep1 set-rc
mut set_bit_stayed       rep1 bit-did-not-move
mut nwords               rep1 nwords
mut chain_b_et_alive     rep1 chain-b-et-alive
mut chain_a_none_bytes   rep1 chain-bytes
mut mode_exit            rep1 mode-exit
mut kernel_sha           rep1 kernel-sha
mut splat                rep1 splat
mut grid_live_to_dead    rep2 rep1-ne-rep2

echo "SUMMARY|selftest=$((pass+fail))|passed=$pass|failed=$fail"
[ "$fail" = "0" ] || exit 1
