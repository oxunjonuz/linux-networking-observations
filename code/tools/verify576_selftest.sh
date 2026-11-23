#!/bin/bash
# verify576_selftest.sh -- does verify576.py actually go red?
#
# The baseline is rep1's log copied to both slots (so the determinism check
# passes by construction).  Every mutation below changes exactly one thing in
# one field and must make the verifier exit non-zero *without* a traceback;
# `noop` must stay green; a missing log must exit 1, not crash.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p "$ROOT/tmp"
TMP=$(mktemp -d "$ROOT/tmp/selftest576.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
run() {  # run <dir>
	F576_LOGDIR=$1 python3 tools/verify576.py > "$TMP/out" 2> "$TMP/err"
	echo $?
}
fresh() {
	rm -rf "$TMP/d"; mkdir -p "$TMP/d"
	cp -f logs/f54_rep1.log "$TMP/d/f54_rep1.log"
	cp -f logs/f54_rep1.log "$TMP/d/f54_rep2.log"
}
mut() {  # mut <name> <python-expression on the text>
	fresh
	python3 - "$TMP/d" "$1" <<'PY'
import sys, io
d, name = sys.argv[1], sys.argv[2]
p = d + "/f54_rep1.log"
s = open(p, errors="replace").read()
old = s
if name == "door":
    s = s.replace("F576 C|g6=1|f6=1|n1=1|e0=1|e1=1|r0=1|ch0=-1",
                  "F576 C|g6=2|f6=1|n1=1|e0=1|e1=1|r0=1|ch0=-1", 1)
elif name == "ch0":
    s = s.replace("ch0=1|ch1=1", "ch0=0|ch1=1", 1)
elif name == "ch1":
    s = s.replace("ch0=1|ch1=1", "ch0=1|ch1=0", 1)
elif name == "wire":
    s = s.replace("v102p_d=1|v102b_d=66", "v102p_d=0|v102b_d=66", 1)
elif name == "v101":
    s = s.replace("v101p_d=0|v101b_d=0", "v101p_d=1|v101b_d=0", 1)
elif name == "x0rxb":
    s = s.replace("x0rxb_d=80", "x0rxb_d=84", 1)
elif name == "tap":
    s = s.replace("t0=x0:1:80:", "t0=x0:1:84:", 1)
elif name == "vtci":
    s = s.replace(":1:8100:0066:66:", ":1:8100:0065:66:", 1)
elif name == "plen":
    s = s.replace(":1:8100:0066:66:", ":1:8100:0066:80:", 1)
elif name == "i6in":
    s = s.replace("i6in_d=2|", "i6in_d=3|", 1)
elif name == "frame":
    s = s.replace("F576 FRM|t=", "F576 FRM|q=")
elif name == "dspl":
    s = s.replace("spl0=0|spl1=1|dspl=1", "spl0=0|spl1=0|dspl=0", 1)
elif name == "warnline":
    i = s.index("invalid VLAN protocol")
    j = s.rindex("\n", 0, i)
    k = s.index("\n", i)
    s = s[:j] + s[k:]
elif name == "ksha":
    s = s.replace("### sha256: ", "### sha256: 0", 1)
elif name == "armname":
    s = s.replace("F576 A|arm=ctl|", "F576 A|arm=ctlz|", 1)
elif name == "imm0":
    s = s.replace("|imm0=0067|", "|imm0=0068|", 1)
elif name == "det":
    s = open(d + "/f54_rep2.log", errors="replace").read()
    s = s.replace("F576 C|g6=1|f6=1|n1=1|e0=1|e1=1|r0=1|ch0=-1",
                  "F576 C|g6=0|f6=1|n1=1|e0=1|e1=1|r0=1|ch0=-1", 1)
    open(d + "/f54_rep2.log", "w").write(s)
    sys.exit(0)
elif name == "noop":
    pass
else:
    raise SystemExit("unknown mutation " + name)
assert s != old, "mutation " + name + " did not change the log"
open(p, "w").write(s)
PY
}

ok=0; bad=0
fresh
rc=$(run "$TMP/d")
if [ "$rc" = "0" ] && ! grep -q Traceback "$TMP/err"; then ok=$((ok+1)); else bad=$((bad+1)); echo "BASE rc=$rc"; head -3 "$TMP/out" "$TMP/err"; fi

for m in door ch0 ch1 wire v101 x0rxb tap vtci plen i6in frame dspl warnline ksha armname imm0 det; do
	mut "$m"
	rc=$(run "$TMP/d")
	if [ "$rc" != "0" ] && ! grep -q Traceback "$TMP/err"; then
		ok=$((ok+1))
	else
		bad=$((bad+1)); echo "MUT $m rc=$rc"; head -3 "$TMP/out" "$TMP/err"
	fi
done

fresh; mv "$TMP/d/f54_rep1.log" "$TMP/d/gone.log"
rc=$(run "$TMP/d")
if [ "$rc" != "0" ] && ! grep -q Traceback "$TMP/err"; then ok=$((ok+1)); else bad=$((bad+1)); echo "MISSING rc=$rc"; fi

echo "selftest: $ok ok, $bad bad"
[ "$bad" = "0" ]
