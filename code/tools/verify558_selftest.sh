#!/bin/bash
# verify558_selftest.sh -- does verify558.py ever go red?
#
# The verifier has 340 checks and, in this project, a verifier that has never
# been seen to fail is not evidence (F33: two checks were vacuous because they
# looked up a key that fields() had never produced).  Each mutation below edits
# a COPY of the logs in a temp directory in one specific way and must make the
# verifier fail; the unmutated copies must pass.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
TMP=$(mktemp -d)
pass=0
fail=0

fresh() {  # fresh -> copies the three logs into $TMP
	rm -rf "$TMP"/*
	cp logs/f36_V_rep1.log logs/f36_V_rep2.log logs/f36_T_rep1.log \
	   logs/f36_ipv6_rep1.log "$TMP"/
}

runv() { F36_LOGDIR=$TMP python3 tools/verify558.py > "$TMP/out.txt" 2>&1; echo $?; }

mut() {  # mut <name> <file> <python-edit>
	local name=$1 file=$2 edit=$3 rc
	fresh
	python3 - "$TMP/$file" "$edit" <<'EOF'
import sys
p, edit = sys.argv[1], sys.argv[2]
s = open(p, errors="replace").read()
old, new = edit.split("|||")
assert old in s, "MUTATION TARGET NOT FOUND: " + old
open(p, "w").write(s.replace(old, new, 1))
EOF
	[ $? -ne 0 ] && { echo "MUT $name: target not found"; fail=$((fail+1)); return; }
	rc=$(runv)
	nf=$(grep -c '^FAIL' "$TMP/out.txt")
	if [ "$rc" = "0" ]; then
		echo "MUT $name: SURVIVED (verifier still green)"
		fail=$((fail+1))
	elif [ "$nf" = "0" ]; then
		# a crash is not a catch: the verifier must say WHICH check broke
		echo "MUT $name: verifier crashed instead of reporting a check"
		tail -3 "$TMP/out.txt" | sed 's/^/    /'
		fail=$((fail+1))
	else
		echo "MUT $name: caught ($nf failing checks)"
		pass=$((pass+1))
	fi
}

# baseline: the real logs must pass
fresh
rc=$(runv)
if [ "$rc" = "0" ]; then
	echo "BASE: green ($(grep '^SUMMARY' "$TMP/out.txt"))"
	pass=$((pass+1))
else
	echo "BASE: RED -- $(grep '^FAIL' "$TMP/out.txt" | head -5)"
	fail=$((fail+1))
fi

# 1. a live cell in the vd grid becomes 0
mut M1_live_cell_zero f36_V_rep1.log \
	'F558 RUN|env=vd|arm=g8_2|off=8|len=2|rc=0|acks=1|snd=0|cnt0=0|cnt=1|||F558 RUN|env=vd|arm=g8_2|off=8|len=2|rc=0|acks=1|snd=0|cnt0=0|cnt=0'
# 2. a dead cell in the v0 grid becomes 1
mut M2_dead_cell_alive f36_V_rep2.log \
	'F558 RUN|env=v0|arm=g16_2|off=16|len=2|rc=0|acks=1|snd=0|cnt0=0|cnt=0|||F558 RUN|env=v0|arm=g16_2|off=16|len=2|rc=0|acks=1|snd=0|cnt0=0|cnt=1'
# 3. the "no envelope" control becomes 1
mut M3_novd_ctl_one f36_V_rep1.log \
	'F558 RUN|env=novd|arm=ctl|off=-1|len=0|rc=0|acks=1|snd=0|cnt0=0|cnt=0|||F558 RUN|env=novd|arm=ctl|off=-1|len=0|rc=0|acks=1|snd=0|cnt0=0|cnt=1'
# 4. the far side's IpInReceives for the vid-0 store
mut M4_ipin_wrong f36_V_rep1.log \
	'arm=s14_0|off=14|len=2|rc=0|acks=1|snd=0|cnt0=0|cnt=1|live=1|ipin=2|||arm=s14_0|off=14|len=2|rc=0|acks=1|snd=0|cnt0=0|cnt=1|live=1|ipin=0'
# 5. the byte change of the ethertype store is undone
mut M5_bytes_reverted f36_V_rep1.log \
	'arm=s16_2|view=tx|n=60|skip=0|pt=4|nchg=1|chg=13:00>06|hex=ffffffffffffaabbcc0000660806450000|||arm=s16_2|view=tx|n=60|skip=0|pt=4|nchg=0|chg=-|hex=ffffffffffffaabbcc0000660800450000'
# 6. the tagged control frame in `why` stops matching the plain one
mut M6_tagged_eq_plain f36_V_rep1.log \
	'F558 WHY|tagged|arm=rx_r0|n=60|skip=0|pt=1|vs_plain=-|hex=ffffffffffffaabbcc0000660800|||F558 WHY|tagged|arm=rx_r0|n=60|skip=0|pt=1|vs_plain=13:01>64|hex=ffffffffffffaabbcc0000810000640800'
# 7. one send, two counts
mut M7_one_send_two f36_T_rep1.log \
	'F558 WHY|one_send|cnt_delta=1|msgs=1|||F558 WHY|one_send|cnt_delta=2|msgs=1'
# 8. the kernel sha in the log header no longer matches the image
mut M8_kernel_sha f36_V_rep2.log \
	'### sha256: 459f02a507ac748f7ae7b13aaa4982852520cf2d01347b1b9c2519af2bc65843|||### sha256: 459f02a507ac748f7ae7b13aaa4982852520cf2d01347b1b9c2519af2bc65844'
# 9. the vlan device "succeeds" on T557
mut M9_t557_vlandev f36_T_rep1.log \
	'F558 VLANDEV|add_rc=-95|idx=-1|||F558 VLANDEV|add_rc=0|idx=11'
# 10. a dead arm claims the rule saw a frame
mut M10_dead_nfl f36_V_rep1.log \
	'arm=s16_2_plain|off=16|len=2|rc=0|acks=1|snd=0|cnt0=0|cnt=0|live=0|ipin=2|nfl=0|||arm=s16_2_plain|off=16|len=2|rc=0|acks=1|snd=0|cnt0=0|cnt=0|live=0|ipin=2|nfl=46'
# 11. a captured frame claims to be 64 bytes (i.e. the tag came back)
mut M11_frame_len f36_V_rep1.log \
	'arm=ctl|view=tx|n=60|skip=0|pt=4|||arm=ctl|view=tx|n=64|skip=0|pt=4'
# 12. rep2 disagrees with rep1 on one cell
mut M12_determinism f36_V_rep2.log \
	'F558 RUN|env=vd|arm=g10_4|off=10|len=4|rc=0|acks=1|snd=0|cnt0=0|cnt=1|||F558 RUN|env=vd|arm=g10_4|off=10|len=4|rc=0|acks=1|snd=0|cnt0=0|cnt=0'

# 13. one more honest invariant: T557 and T558 must agree on the p4 grid
mut M14_t557_p4 f36_T_rep1.log \
	'F557 R|env=p4|arm=g6_2|off=6|len=2|kind=0|fast=1|rc=0|acks=1|cnt=1|||F557 R|env=p4|arm=g6_2|off=6|len=2|kind=0|fast=1|rc=0|acks=1|cnt=0'

echo "SELFTEST|passed=$pass|failed=$fail"
rm -rf "$TMP"
[ "$fail" = "0" ]
