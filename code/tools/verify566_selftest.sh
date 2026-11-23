#!/bin/bash
# verify566_selftest.sh -- does verify566.py have teeth?
#
# Baseline: the verifier on the two real logs must be green.
# Then: one single-field mutation per case, applied to a COPY of the logs; the
# verifier must go red AND the failure must be the one that mutation targets.
# A crash of the verifier does not count as a caught mutation (F38's lesson).
set -uo pipefail
cd /work/kernel-sec
R1=logs/f44_rep1.log
R2=logs/f44_rep2.log
TMP=$(mktemp -d /tmp/f566selftest.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

run_verify() {  # run_verify <log1> <log2> -> exit code, output in $TMP/out.txt
	F44_LOGS="$1,$2" python3 tools/verify566.py >"$TMP/out.txt" 2>&1
	echo $?
}

echo "== baseline =="
rc=$(run_verify "$R1" "$R2")
if [ "$rc" != "0" ]; then
	echo "BASELINE_RED (exit $rc)"
	tail -20 "$TMP/out.txt"
	exit 1
fi
grep -q "VERIFY566 OK" "$TMP/out.txt" || { echo "BASELINE_NO_OK"; exit 1; }
echo "baseline green: $(grep -o 'checks: [0-9]* ok' "$TMP/out.txt")"

pass=0
fail=0
mutate() {  # mutate <name> <expect-substring> <which-log>
	local name=$1 want=$2 which=${3:-1}
	local a=$TMP/m1.log b=$TMP/m2.log
	cp "$R1" "$a"; cp "$R2" "$b"
	if [ "$which" = "1" ]; then
		python3 tools/f566_mutate.py "$name" "$R1" "$a" || { echo "$name MUTATE_FAIL"; fail=$((fail+1)); return; }
	else
		python3 tools/f566_mutate.py "$name" "$R2" "$b" || { echo "$name MUTATE_FAIL"; fail=$((fail+1)); return; }
	fi
	local rc
	rc=$(run_verify "$a" "$b")
	if [ "$rc" = "0" ]; then
		echo "$name NOT_CAUGHT"
		fail=$((fail+1))
		return
	fi
	if grep -q "Traceback" "$TMP/out.txt"; then
		echo "$name VERIFIER_CRASHED"
		fail=$((fail+1))
		return
	fi
	if ! grep -qF "$want" "$TMP/out.txt"; then
		echo "$name WRONG_CHECK (wanted '$want')"
		grep '^FAIL' "$TMP/out.txt" | head -3
		fail=$((fail+1))
		return
	fi
	echo "$name caught"
	pass=$((pass+1))
}

echo "== mutations =="
mutate ctl_passes   "ctl passes td/ndg/p"
mutate store_lives  "live td/ipp/p/t4_2"
mutate post_byte    "the store landed at data"
mutate pre_byte     "the store landed at data"
mutate rhex         "leaves the MAC addresses alone"
mutate rchgs        "the far frame changed exactly at"
mutate u5001        "delivers the datagram to 5001"
mutate ihdr         "one IP header error"
mutate itrun        "a truncated packet, not a header error"
mutate md_rn        "the frame is forwarded after all"
mutate frame        "the logged payload IS the frame"
mutate kernel       "the boot is 7.3.4-T563"
mutate splat        "no splat in"
mutate drop_arm     "348 arms expected"
mutate rep2_arm     "every F566 A line is identical" 2
mutate npre         "the first chain logged exactly as often"
mutate l2           "NFULA_L2HDR present only at the netdev door"
mutate imm          "carries the immediate"

echo ""
echo "selftest: $pass caught, $fail not"
[ "$fail" = "0" ] || exit 1
echo "SELFTEST_OK"
