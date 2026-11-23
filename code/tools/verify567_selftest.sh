#!/bin/bash
# verify567_selftest.sh -- does verify567.py have teeth?
#
# Baseline: the verifier on the two real logs must be green.
# Then: one single-field mutation per case, applied to a COPY of one log; the
# verifier must go red AND the failure must be the one that field owns.
# A crash of the verifier does not count as a caught mutation (F38's lesson).
set -uo pipefail
cd /work/kernel-sec
R1=logs/f45_rep1.log
R2=logs/f45_rep2.log
TMP=$(mktemp -d /tmp/f567selftest.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

run_verify() {
	F45_LOGS="$1,$2" python3 tools/verify567.py >"$TMP/out.txt" 2>&1
	echo $?
}

echo "== baseline =="
rc=$(run_verify "$R1" "$R2")
if [ "$rc" != "0" ]; then
	echo "BASELINE_RED (exit $rc)"
	tail -25 "$TMP/out.txt"
	exit 1
fi
grep -q "VERIFY567 OK" "$TMP/out.txt" || { echo "BASELINE_NO_OK"; exit 1; }
echo "baseline green: $(grep -o 'checks=[0-9]* ok=[0-9]*' "$TMP/out.txt")"

pass=0; fail=0
mutate() {  # mutate <name> <expect-substring> <which>
	local name=$1 want=$2 which=${3:-1}
	local a=$TMP/m1.log b=$TMP/m2.log
	cp "$R1" "$a"; cp "$R2" "$b"
	if [ "$which" = "1" ]; then
		python3 tools/f567_mutate.py "$name" "$R1" "$a" || { echo "$name MUTATE_FAIL"; fail=$((fail+1)); return; }
	else
		python3 tools/f567_mutate.py "$name" "$R2" "$b" || { echo "$name MUTATE_FAIL"; fail=$((fail+1)); return; }
	fi
	local rc; rc=$(run_verify "$a" "$b")
	if [ "$rc" = "0" ]; then echo "$name NOT_CAUGHT"; fail=$((fail+1)); return; fi
	if grep -q "Traceback" "$TMP/out.txt"; then echo "$name VERIFIER_CRASHED"; fail=$((fail+1)); return; fi
	if ! grep -qF "$want" "$TMP/out.txt"; then
		echo "$name WRONG_CHECK (wanted '$want')"
		grep '^FAIL' "$TMP/out.txt" | head -3
		fail=$((fail+1)); return
	fi
	echo "$name caught"; pass=$((pass+1))
}

echo "== mutations =="
mutate lives        "the chain counter counts the rule"
mutate lives_up     "a refused write leaves the counter at 0"
mutate cnts         "the rule runs once per copy"
mutate post_byte    "NFLOG payload == model of the write"
mutate post_drop    "refusal shows up as an empty NFLOG payload"
mutate i6in         "Ip6InReceives"
mutate i6hdr        "Ip6InHdrErrors"
mutate i6trun       "Ip6InTruncatedPkts"
mutate i6deliv      "Ip6InDelivers"
mutate u6a          "socket 5000 vs the untouched frame"
mutate u6b          "socket 5001 vs the bytes"
mutate ctl_counter  "control counter"
mutate frame_byte   "walk(hb)"
mutate frame_len    "the logged length of hbdo"
mutate kernel       "kernel sha in the log"
mutate splat        "no KASAN"
mutate drop_arm     "the same number of arms"
mutate imm          "NFLOG payload == model of the write"
mutate mode3        "meta verdict"
mutate xc           "cross-family counter"
mutate v6on         "IPv6 is on for br0 only"
mutate sock         "IPv6 sockets bound"
mutate post_byte    "rep1 == rep2, arm for arm" 2

echo ""
echo "selftest: $pass caught, $fail not"
[ "$fail" = "0" ] || exit 1
echo "SELFTEST_OK"
