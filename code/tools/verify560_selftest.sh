#!/bin/bash
# verify560_selftest.sh -- the verifier must be able to go red.
#
# Baseline: the real logs must pass.  Then each mutation of ONE field in a copy
# of the logs must make verify560.py fail with the FAIL line that OWNS that
# field -- not merely any FAIL.  A mutation that crashes the verifier
# (Traceback) is not counted as caught, and a mutation whose anchor does not
# exist is counted as broken, not as a pass.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
pass=0
fail=0
T=$(mktemp -d /tmp/v560.XXXXXX)
trap 'rm -rf "$T"' EXIT

baseline() {
	rm -rf "$T"
	mkdir -p "$T"
	cp logs/f38_rep1.log "$T/f38_rep1.log"
	cp logs/f38_rep2.log "$T/f38_rep2.log"
}

run() {
	python3 tools/verify560.py --logdir "$T" > "$T/out.txt" 2>&1
	echo $?
}

baseline
rc=$(run)
if [ "$rc" = "0" ] && grep -q ", 0 failed" "$T/out.txt"; then
	echo "BASELINE ok ($(grep -o '[0-9]* checks' "$T/out.txt"))"
	pass=$((pass+1))
else
	echo "BASELINE RED rc=$rc"
	tail -5 "$T/out.txt"
	fail=$((fail+1))
fi

mut() {  # mut <rule> <log> <expected FAIL substring>
	local rule=$1 file=$2 want=$3
	baseline
	if ! python3 tools/f38_mutate.py "$T/f38_$file.log" "$rule" > "$T/mut.txt" 2>&1; then
		echo "MUT-BROKEN $rule: $(tail -1 "$T/mut.txt")"
		fail=$((fail+1))
		return
	fi
	local rc
	rc=$(run)
	if [ "$rc" != "0" ] && ! grep -q "Traceback" "$T/out.txt" \
	   && grep -q "^FAIL $want" "$T/out.txt"; then
		echo "MUT-CAUGHT $rule -> $(grep -m1 "^FAIL $want" "$T/out.txt" | cut -c1-100)"
		pass=$((pass+1))
	else
		echo "MUT-SURVIVED $rule (want FAIL $want) rc=$rc"
		grep -m3 '^FAIL' "$T/out.txt" | cut -c1-100
		fail=$((fail+1))
	fi
}

mut live_to_dead     rep1 model.recv.w100.g16_2
mut dead_to_live     rep1 model.recv.p.g16_1
mut ingress_dead     rep1 model.ndin.x91.g20_1
mut egress_alive     rep1 model.ndeg.s8100.g0_2
mut arp_past         rep1 bytes.arp.aw100.span
mut wire_byte        rep1 bytes.x91.wire.12_16
mut far_byte         rep1 bytes.far.p.equals.far.w100
mut probe_m100       rep1 probe.m100.ctl.wire.equals.plain
mut tagstore_rc      rep1 probe.tagstore.installed
mut ttl_index        rep1 bytes.ttl.tagged.at.26
mut drop_refused     rep1 drop.p16_2.refused.and.no.frame
mut drop_delivered   rep1 drop.w16_2.accepted.and.delivered
mut mode_exit        rep1 boot.rep1.MODE_EXIT=0
mut kernel_sha       rep1 prov.kernel.sha.matches.file
mut splat            rep1 boot.rep1.no.splat
mut arm_dropped      rep1 model.arms.count
mut live_to_dead     rep2 det.identical.lines

echo "SUMMARY|selftest=$((pass+fail))|passed=$pass|failed=$fail"
[ "$fail" = "0" ] || exit 1
