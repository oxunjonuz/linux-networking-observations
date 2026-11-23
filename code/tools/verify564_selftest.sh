#!/bin/bash
# verify564_selftest.sh -- can verify564.py go red at all?
#
# Baseline: the real logs must pass.  Then one mutation at a time is applied
# to a COPY of the two logs and the verifier must fail.  A mutation the
# verifier does not notice is a hole in the verifier, not a result about the
# kernel; a verifier crash or a missing log is NOT counted as a caught
# mutation (the harness checks the exit code is exactly 1 and that at least
# one FAIL line was printed).
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
L1=$ROOT/logs/f42_rep1.log
L2=$ROOT/logs/f42_rep2.log
pass=0
fail=0
note() { printf '%-22s %s\n' "$1" "$2"; }

run_verify() {  # run_verify <l1> <l2>
	F42_LOGS="$1,$2" python3 tools/verify564.py > "$TMP/out.txt" 2>&1
	echo $?
}

base=$(F42_LOGS="$L1,$L2" python3 tools/verify564.py 2>&1)
echo "$base" | tail -3
if echo "$base" | grep -q "^checks: .* 0 failed" && [ $? -eq 0 ]; then
	note "baseline" "green"
	pass=$((pass+1))
else
	note "baseline" "RED -- the real logs do not pass; nothing below is meaningful"
	fail=$((fail+1))
fi

# one mutation of rep1 at a time
muts="frame_pppoe_len frame_sid frame_payload frame_ethertype v6frame_len
      v6frame_proto udp4_bytes ctl_prx ctl_ipin ttl_ihdr daddr_ihdr
      ttlsame_delivery id4_prx idbig_prx ll6_live ll13_ipin pre88ff hop_urn
      hop_urhex hdrbad_hdr hdrbad_deliv novlan_arc shavlan_reply opvlan_reply
      livedelta rhex"
for m in $muts; do
	if ! python3 tools/f42_mutate.py "$L1" "$TMP/m1.log" "$m" 2>"$TMP/mut.err"; then
		note "$m" "SKIP (mutation did not apply: $(head -1 "$TMP/mut.err"))"
		fail=$((fail+1))
		continue
	fi
	rc=$(run_verify "$TMP/m1.log" "$L2")
	if [ "$rc" = "1" ] && grep -q "^FAIL: " "$TMP/out.txt"; then
		note "$m" "caught ($(grep -c '^FAIL: ' "$TMP/out.txt") checks red)"
		pass=$((pass+1))
	else
		note "$m" "SURVIVED (rc=$rc)"
		fail=$((fail+1))
	fi
done

# the second boot matters: break rep2 only
python3 tools/f42_mutate.py "$L2" "$TMP/m2.log" ctl_prx >/dev/null 2>&1
rc=$(run_verify "$L1" "$TMP/m2.log")
if [ "$rc" = "1" ] && grep -q "^FAIL: " "$TMP/out.txt"; then
	note "rep2_only" "caught"
	pass=$((pass+1))
else
	note "rep2_only" "SURVIVED (rc=$rc)"
	fail=$((fail+1))
fi

# a missing log must fail, not pass silently
rc=$(run_verify "$L1" "$TMP/does-not-exist.log")
if [ "$rc" = "1" ]; then
	note "missing_log" "caught"
	pass=$((pass+1))
else
	note "missing_log" "SURVIVED (rc=$rc)"
	fail=$((fail+1))
fi

echo "selftest: $pass passed, $fail failed"
[ "$fail" = "0" ]
