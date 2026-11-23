#!/bin/bash
# verify568_selftest.sh -- does verify568.py have teeth?
#
# Baseline: the verifier on the two real logs must be green.
# Then: one single-field mutation per case, applied to a COPY of one log; the
# verifier must go red AND the failure must be the one that field owns.
# A crash of the verifier does not count as a caught mutation (F38's lesson).
set -uo pipefail
cd /work/kernel-sec
R1=logs/f46_rep1.log
R2=${R2:-logs/f46_rep2.log}
TMP=$(mktemp -d /tmp/f568selftest.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

run_verify() {
	python3 tools/verify568.py --run1 "$1" --run2 "$2" >"$TMP/out.txt" 2>&1
	echo $?
}

echo "== baseline =="
rc=$(run_verify "$R1" "$R2")
if [ "$rc" != "0" ]; then
	echo "BASELINE_RED (exit $rc)"
	tail -25 "$TMP/out.txt"
	exit 1
fi
grep -q "failures=0" "$TMP/out.txt" || { echo "BASELINE_NOT_OK"; exit 1; }
echo "baseline green: $(grep -o 'checks=[0-9]*' "$TMP/out.txt" | head -1)"

pass=0; fail=0
mutate() {  # mutate <name> <expect-substring> <which>
	local name=$1 want=$2 which=${3:-1}
	local a=$TMP/m1.log b=$TMP/m2.log
	cp "$R1" "$a"; cp "$R2" "$b"
	if [ "$which" = "1" ]; then
		python3 tools/f568_mutate.py "$name" "$R1" "$a" || { echo "$name MUTATE_FAIL"; fail=$((fail+1)); return; }
	else
		python3 tools/f568_mutate.py "$name" "$R2" "$b" || { echo "$name MUTATE_FAIL"; fail=$((fail+1)); return; }
	fi
	local rc; rc=$(run_verify "$a" "$b")
	if [ "$rc" = "0" ]; then echo "$name NOT_CAUGHT"; fail=$((fail+1)); return; fi
	if grep -q "Traceback" "$TMP/out.txt"; then echo "$name VERIFIER_CRASHED"; fail=$((fail+1)); return; fi
	if ! grep -qF "$want" "$TMP/out.txt"; then
		echo "$name WRONG_CHECK (wanted '$want')"
		grep '^  FAIL' "$TMP/out.txt" | head -3
		fail=$((fail+1)); return
	fi
	echo "$name caught"; pass=$((pass+1))
}

echo "== mutations =="
mutate lives      "guard verdict"
mutate lives_up   "guard verdict"
mutate cntp       "the packet reached the door"
mutate wire_byte  "every byte outside the noise set"
mutate wire_noframe "left no frame on the wire"
mutate udpn       "delivered to the socket"
mutate ihdr       "a bad header checksum is InHdrErrors"
mutate udperr     "a bad udp checksum is UdpInErrors"
mutate precv      "the udp checksum catches what the ip layer let through"
mutate pnr        "has no route"
mutate tapn       "the receiver's tap saw the frame"
mutate noise      "noise is only the ip id"
mutate sport      "the received source port is the wire one"
mutate imm        "every byte outside the noise set"
mutate off        "guard verdict"
mutate base       "every byte outside the noise set"
mutate phdr       "does not re-check the header checksum"
mutate pdeliv     "the packet is delivered to the ip layer"
mutate pay        "the received payload is the wire payload"
mutate rcp        "the door chain installed"
mutate frame_len  "same frame length"
mutate lives2     "guard verdict" 2

echo "== summary: pass=$pass fail=$fail =="
[ "$fail" = "0" ] || exit 1
