#!/bin/bash
# verify587_selftest.sh -- does verify587.py go RED on a wrong log, and only on
# a wrong log?  Every mutation below changes exactly one clause of one line;
# the base line must be green and every mutation must fail WITHOUT a traceback
# (a verifier that crashes is not a verifier that noticed).
set -uo pipefail
ROOT=/work/kernel-sec
V="$ROOT/tools/verify587.py"
R1="$ROOT/logs/f65_rep1.log"
R2="$ROOT/logs/f65_rep2.log"
T=/tmp/f65_st
mkdir -p "$T"
pass=0; fail=0

run() {  # run <name> <expect: green|red> <file1> <file2>
	local name=$1 want=$2 f1=$3 f2=$4 out rc
	out=$(python3 "$V" "$f1" "$f2" 2>&1); rc=$?
	if printf '%s' "$out" | grep -q "Traceback"; then
		echo "SELFTEST CRASH|$name"; fail=$((fail+1)); return
	fi
	if [ "$want" = green ] && [ $rc -eq 0 ]; then pass=$((pass+1)); return; fi
	if [ "$want" = red ] && [ $rc -ne 0 ]; then pass=$((pass+1)); return; fi
	echo "SELFTEST WRONG|$name|rc=$rc|want=$want"; printf '%s\n' "$out" | tail -3
	fail=$((fail+1))
}

mut() {  # mut <name> <python expr producing the new text>
	local name=$1 expr=$2
	cp "$R1" "$T/m1.log"
	python3 - "$T/m1.log" <<PY || { echo "MUT_FAIL|$name"; fail=$((fail+1)); return; }
import sys
p = "$T/m1.log"
s = open(p, errors="replace").read()
$expr
open(p, "w").write(s)
PY
	run "$name" red "$T/m1.log" "$R2"
}

cp "$R1" "$T/base1.log"; cp "$R2" "$T/base2.log"
run baseline green "$T/base1.log" "$T/base2.log"
run noop green "$T/base1.log" "$T/base2.log"

# --- one clause at a time -------------------------------------------------
mut lg6        's = s.replace("lg6=0208|lgudp=aa3c13880208fcc2", "lg6=0209|lgudp=aa3c13880208fcc2", 1)'
mut lgudpck    's = s.replace("lgudp=aa3c13880208fcc2", "lgudp=aa3c13880208fcc3", 1)'
mut lgudplen   's = s.replace("lgudp=aa3c13880208fcc2", "lgudp=aa3c13880209fcc2", 1)'
mut lgplen     's = s.replace("lgn=1|lgplen=560|lg2=-1", "lgn=1|lgplen=561|lg2=-1", 1)'
mut lgp0       's = s.replace("lgp0=0081828384858687", "lgp0=0081828384858688", 1)'
mut ch         's = s.replace("exp=1|ch=1|ch0=1|agr=1", "exp=1|ch=2|ch0=1|agr=1", 1)'
mut agr        's = s.replace("ch=1|ch0=1|agr=1", "ch=1|ch0=1|agr=0", 1)'
mut rcvn       's = s.replace("att=1|n=1|n2=0", "att=1|n=2|n2=0", 1)'
mut rcvL       's = s.replace("L=512,0,0,0,0,0,-1,512", "L=512,0,0,0,0,0,-1,511", 1)'
mut rcvB       's = s.replace("B=0,0,0,0,0,0,-1,0", "B=1,0,0,0,0,0,-1,0", 1)'
mut rcvT       's = s.replace("T=201,0,0,0,0,0,-1,201", "T=901,0,0,0,0,0,-1,90)'
mut rcvwany    's = s.replace("wany=1|w520=1", "wany=2|w520=1", 1)'
mut rcvudp     's = s.replace("udp=1|udperr=0", "udp=2|udperr=0", 1)'
mut rcverr     's = s.replace("udp=4|udperr=0", "udp=4|udperr=)'
mut tapflen    's = s.replace("dev=y3b|k=0|flen=574", "dev=y3b|k=0|flen=575", 1)'
mut tapck      's = s.replace("uhlen=520|uhck=fcc2", "uhlen=520|uhck=fcc)'
mut tapstat    's = s.replace("uhck=fcc2|stat=9", "uhck=fcc2|stat=)'
mut taphop     's = s.replace("hop=63|uhlen=520|uhck=fcc2", "hop=64|uhlen=520|uhck=fcc)'
mut tappayload 's = s.replace("hex=6ec9107b21b2", "hex=6ec9107b21b3", 1)'
mut delarm     's = "\n".join(l for l in s.split("\n") if not l.startswith("F587 ARM|i=00|")) + "\n"'
mut msg2       's = s.replace("lg2=12048", "lg2=12049", 1)'
mut win        's = s.replace("|WIN=700", "|WIN=60)'
mut shape      's = s.replace("lgplen=1072|lg2=-1", "lgplen=1071|lg2=-1", 1)'
mut second     's = s.replace("name=l_one_b", "name=l_one_x", 1)'

echo "SELFTEST|pass=$pass fail=$fail"
[ $fail -eq 0 ]
