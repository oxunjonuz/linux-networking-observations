#!/bin/bash
# verify586_selftest.sh -- can verify586.py go red?  One single-clause
# mutation of a recorded log at a time; the verifier must FAIL without a
# traceback.  A noop copy must stay green, a missing log must be red and not
# a crash.
set -uo pipefail
cd /work/kernel-sec
V="python3 tools/verify586.py"
L1=logs/f64_rep1_final.log
L2=logs/f64_rep2_final.log
T=/tmp/f64_st
rm -rf $T; mkdir -p $T
pass=0; fail=0

mutate() {  # mutate <logA> <logB>   (expression in $MUTEXPR)
	python3 - "$@" <<'PY2'
import os, sys
expr = os.environ["MUTEXPR"]
for p in sys.argv[1:]:
    s = open(p, errors="replace").read()
    old = s
    s = eval(expr)
    if s == old:
        sys.stderr.write("MUTATION DID NOT APPLY\n")
        sys.exit(9)
    open(p, "w").write(s)
PY2
}

run() {  # run <name> <expect: red|green> <expression, "-" for noop>
	local name=$1 want=$2 expr=$3 out rc
	cp $L1 $T/a.log; cp $L2 $T/b.log
	if [ "$expr" != "-" ]; then
		MUTEXPR="$expr" mutate $T/a.log $T/b.log || {
			echo "SELFTEST MUTATION_FAILED $name"; fail=$((fail+1)); return; }
	fi
	out=$($V $T/a.log $T/b.log 2>&1); rc=$?
	if echo "$out" | grep -q "Traceback"; then
		echo "SELFTEST CRASH $name"; fail=$((fail+1)); return
	fi
	if [ "$want" = red ] && [ $rc -ne 0 ]; then
		pass=$((pass+1)); echo "  red   $name"
	elif [ "$want" = green ] && [ $rc -eq 0 ]; then
		pass=$((pass+1)); echo "  green $name"
	else
		echo "SELFTEST WRONG $name rc=$rc want=$want"
		echo "$out" | tail -3
		fail=$((fail+1))
	fi
}

A1='s.replace("|ch=1|nl=1|lgn=1|lgplen=1584", "|ch=1|nl=1|lgn=1|lgplen=1580", 1)'
A2='s.replace("|lgudp=aa3c13880608fcc2|", "|lgudp=aa3c13880608fcc3|", 1)'
A3='s.replace("|lgp3=a0a1a2a384858687", "|lgp3=a0a1a2a384858688", 1)'
A4='s.replace("name=g_eq_a|src=F|dst=a|xg=f|n=3", "name=g_eq_a|src=F|dst=a|xg=f|n=4", 1)'
A5='s.replace("|uhlen=208|uhck=fb8b", "|uhlen=200|uhck=fb8b", 1)'
A6='s.replace("|i=03|dev=y4|k=1|flen=574|len=574|trunc=0|iplen=520|hop=64", "|i=03|dev=y4|k=1|flen=574|len=574|trunc=0|iplen=520|hop=63", 1)'
A7='s.replace("|uhlen=520|uhck=02b0|stat=129", "|uhlen=520|uhck=02b0|stat=9", 1)'
A8='s.replace("|flen=262|", "|flen=258|", 1)'
A9='s.replace("|udperr=4|", "|udperr=3|", 1)'
A10='s.replace("|L=24,0,0,0,0,0,-1,24|", "|L=32,0,0,0,0,0,-1,32|", 1)'
A11='s.replace("|L=512,512,512,200,0,0,512,200|", "|L=512,512,200,512,0,0,200,512|", 1)'
A12='s.replace("|lg6=06d0|", "|lg6=06cf|", 1)'
A13='s.replace("name=g_t3_w_a|", "name=g_t3_w_q|", 1)'
A14='s.replace("name=g_c65_a|src=F|dst=a|xg=f|n=65", "name=g_c65_a|src=F|dst=a|xg=f|n=64", 1)'

echo "== baseline"
run baseline green -
echo "== single-clause mutations, each must go red"
run m01_nflog_len     red "$A1"
run m02_udp_check     red "$A2"
run m03_tail_store    red "$A3"
run m04_profile       red "$A4"
run m05_tail_uhlen    red "$A5"
run m06_hop_limit     red "$A6"
run m07_auxdata       red "$A7"
run m08_frame_len     red "$A8"
run m09_snmp_error    red "$A9"
run m10_trim24        red "$A10"
run m11_order         red "$A11"
run m12_ipv6_len      red "$A12"
run m13_arm_missing   red "$A13"
run m14_cap_count     red "$A14"
echo "== a missing log is red, not a crash"
out=$($V /nonexistent.log $L2 2>&1); rc=$?
if [ $rc -ne 0 ] && ! echo "$out" | grep -q Traceback; then
	pass=$((pass+1)); echo "  red   m15_missing_log"
else
	echo "SELFTEST WRONG m15 rc=$rc"; fail=$((fail+1))
fi

echo "== selftest: $pass passed, $fail failed"
[ $fail -eq 0 ] || exit 1
