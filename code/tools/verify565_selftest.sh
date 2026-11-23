#!/bin/bash
# verify565_selftest.sh -- is verify565.py able to go red?
#
# Baseline: the untouched logs must pass.  Then one single-field mutation at a
# time, each of which must (a) make the verifier exit 1 -- not crash -- and
# (b) print the check it belongs to.  A verifier crash is NOT a caught
# mutation: a script that dies on any input would otherwise score perfectly.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
TMP=$(mktemp -d /tmp/f565st.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

run_verify() {  # run_verify <dir>; sets RC and OUT
	OUT=$(F43_LOGS="$1/rep1.log,$1/rep2.log" python3 tools/verify565.py 2>&1)
	RC=$?
}

cp logs/f43_rep1.log "$TMP/rep1.orig"
cp logs/f43_rep2.log "$TMP/rep2.orig"

pass=0; fail=0
base_ok=1

reset() { cp "$TMP/rep1.orig" "$TMP/rep1.log"; cp "$TMP/rep2.orig" "$TMP/rep2.log"; }

reset
run_verify "$TMP"
if [ $RC -eq 0 ]; then
	pass=$((pass+1)); echo "BASELINE ok   ($(echo "$OUT" | tail -1))"
else
	base_ok=0; fail=$((fail+1)); echo "BASELINE FAILED"; echo "$OUT" | tail -15
fi

mut() {  # mut <name> <target:1|2|both> <expected substring> [extra-copy]
	local name=$1 target=$2 want=$3
	reset
	if [ "$target" = "1" ] || [ "$target" = "both" ]; then
		python3 tools/f565_mutate.py "$name" "$TMP/rep1.log" >/dev/null || { echo "MUTATOR $name failed"; fail=$((fail+1)); return; }
	fi
	if [ "$target" = "2" ] || [ "$target" = "both" ]; then
		python3 tools/f565_mutate.py "$name" "$TMP/rep2.log" >/dev/null || { echo "MUTATOR $name failed"; fail=$((fail+1)); return; }
	fi
	run_verify "$TMP"
	if [ $RC -ne 1 ]; then
		fail=$((fail+1)); echo "MISS  $name: rc=$RC (want 1)"; echo "$OUT" | tail -3
	elif ! echo "$OUT" | grep -qF "$want"; then
		fail=$((fail+1)); echo "MISS  $name: rc=1 but no '$want'"
		echo "$OUT" | grep FAIL | head -3
	else
		pass=$((pass+1)); echo "CAUGHT $name  <- $want"
	fi
}

mut dead_to_live     1 "the guard's verdict"
mut live_to_dead     1 "the guard's verdict"
mut wrong_byte       1 "exactly the bytes"
mut kernel_sha       1 "kernel sha in the log"
mut initrd_sha       1 "initrd sha in the log"
mut frame_ppp_proto  1 "the guard's verdict"
mut udperr           1 "a broken checksum is counted"
mut u5001            1 "delivered to the WRITTEN port"
mut gate_flip        1 "missing arm"
mut csum_byte        1 "CSUM_INET leaves a valid checksum"
mut splat            1 "no KASAN/BUG/Oops/WARNING"
mut off_field        1 "exactly the bytes"
mut imm_field        1 "exactly the bytes"
mut dead_arm_frame   1 "a refused cell changes nothing"
mut v6_port          1 "CSUM_INET delivers to the written port"
mut reach_ll         1 "reach ll0: the store lands"
mut dead_to_live     2 "byte for byte"

echo "----"
echo "selftest: $pass caught, $fail missed (baseline_ok=$base_ok)"
[ "$base_ok" = "1" ] && [ "$fail" -eq 0 ]
