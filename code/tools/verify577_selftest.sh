#!/bin/bash
# verify577_selftest.sh -- does verify577.py actually go red?
#
# The baseline is rep1's log copied to both slots (so the determinism check
# passes by construction).  Every mutation below changes exactly one field and
# must make the verifier exit non-zero *without* a traceback; `noop` must stay
# green; a missing log must exit 1, not crash.
set -uo pipefail
ROOT=/work/kernel-sec
cd "$ROOT"
mkdir -p "$ROOT/tmp"
TMP=$(mktemp -d "$ROOT/tmp/selftest577.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
run() {  # run <dir>
	F577_LOGDIR=$1 python3 tools/verify577.py > "$TMP/out" 2> "$TMP/err"
	echo $?
}
fresh() {
	rm -rf "$TMP/d"; mkdir -p "$TMP/d"
	cp -f logs/f55_rep1.log "$TMP/d/f55_rep1.log"
	cp -f logs/f55_rep1.log "$TMP/d/f55_rep2.log"
}
mut() {  # mut <name>
	fresh
	python3 - "$TMP/d" "$1" <<'PY'
import re, sys
d, name = sys.argv[1], sys.argv[2]
p = d + "/f55_rep1.log"
s = open(p, errors="replace").read()
old = s
if name == "door":
    s = s.replace("F577 C|f6=1|g6=1|e0=1|e3=0|n1=1|r0=1|ch0=1|ch1=-1",
                  "F577 C|f6=2|g6=1|e0=1|e3=0|n1=1|r0=1|ch0=1|ch1=-1", 1)
elif name == "ch0":
    s = s.replace("|ch0=1|ch1=-1", "|ch0=0|ch1=-1", 1)
elif name == "ch1":
    s = s.replace("|ch0=1|ch1=1", "|ch0=1|ch1=0", 1)
elif name == "demux":
    s = s.replace("v102_d=1|v103_d=0", "v102_d=0|v103_d=0", 1)
elif name == "v103":
    s = s.replace("v103_d=0|x0rxp_d=1", "v103_d=1|x0rxp_d=1", 1)
elif name == "x0rxb":
    s = s.replace("x0rxb_d=80", "x0rxb_d=84", 1)
elif name == "tap":
    s = s.replace("t0=x0:1:80:", "t0=x0:1:84:", 1)
elif name == "atci":
    s = s.replace("atci=24678", "atci=102", 1)
elif name == "atpid":
    s = s.replace("atpid=33024", "atpid=33025", 1)
elif name == "astat":
    s = s.replace("astat=81", "astat=65", 1)
elif name == "r0vtci":
    s = s.replace(":1:8100:6066:66:", ":1:8100:0065:66:", 1)
elif name == "plen":
    s = s.replace(":1:8100:6066:66:", ":1:8100:6066:80:", 1)
elif name == "l2":
    s = s.replace("8100606686dd", "8100006686dd", 1)
elif name == "i6in":
    s = s.replace("i6in_d=2|", "i6in_d=3|", 1)
elif name == "fwd":
    s = s.replace("fwd_d=1|", "fwd_d=0|", 1)
elif name == "frame":
    s = re.sub(r"(F577 FRM\|f3=)(.)",
               lambda m: m.group(1) + ("1" if m.group(2) != "1" else "2"),
               s, count=1)
elif name == "map":
    s = s.replace("F577 Q|dev=x1.102|eg=5:3|in=-",
                  "F577 Q|dev=x1.102|eg=5:4|in=-", 1)
elif name == "ksha":
    s = s.replace("### sha256: ", "### sha256: 0", 1)
elif name == "armname":
    s = s.replace("F577 A|arm=p5_m7|", "F577 A|arm=p5_m7x|", 1)
elif name == "msgn":
    s = s.replace("F577 M|n=6|", "F577 M|n=7|", 1)
elif name == "det":
    t = open(d + "/f55_rep2.log", errors="replace").read()
    t = t.replace("F577 C|f6=1|g6=1|e0=1|e3=0|n1=1|r0=1|ch0=1|ch1=-1",
                  "F577 C|f6=0|g6=1|e0=1|e3=0|n1=1|r0=1|ch0=1|ch1=-1", 1)
    assert t != open(d + "/f55_rep2.log", errors="replace").read()
    open(d + "/f55_rep2.log", "w").write(t)
    sys.exit(0)
elif name == "noop":
    pass
else:
    raise SystemExit("unknown mutation " + name)
if name != "det":
    assert s != old, "mutation " + name + " did not change the log"
    open(p, "w").write(s)
PY
}

ok=0; bad=0
fresh
rc=$(run "$TMP/d")
if [ "$rc" = "0" ] && ! grep -q Traceback "$TMP/err"; then ok=$((ok+1)); else bad=$((bad+1)); echo "BASE rc=$rc"; head -3 "$TMP/out" "$TMP/err"; fi

for m in door ch0 ch1 demux v103 x0rxb tap atci atpid astat r0vtci plen l2 i6in fwd frame map ksha armname msgn det; do
	mut "$m"
	rc=$(run "$TMP/d")
	if [ "$rc" != "0" ] && ! grep -q Traceback "$TMP/err"; then
		ok=$((ok+1))
	else
		bad=$((bad+1)); echo "MUT $m rc=$rc"; head -3 "$TMP/out" "$TMP/err"
	fi
done

fresh; mv "$TMP/d/f55_rep1.log" "$TMP/d/gone.log"
rc=$(run "$TMP/d")
if [ "$rc" != "0" ] && ! grep -q Traceback "$TMP/err"; then ok=$((ok+1)); else bad=$((bad+1)); echo "MISSING rc=$rc"; fi

echo "selftest: $ok ok, $bad bad"
[ "$bad" = "0" ]
