#!/usr/bin/env python3
"""verify587_selftest.py -- does verify587.py go RED on a wrong log, and only
on a wrong log?  Every mutation changes exactly one clause; the base line must
be green and every mutation must fail WITHOUT a traceback (a verifier that
crashes is not a verifier that noticed).  A mutation whose pattern is absent
from the log is a defect of this selftest, not a pass."""
import os
import subprocess
import sys

ROOT = "/work/kernel-sec"
V = f"{ROOT}/tools/verify587.py"
R1 = f"{ROOT}/logs/f65_rep1.log"
R2 = f"{ROOT}/logs/f65_rep2.log"
TMP = "/tmp/f65_st/m1.log"

MUTS = [
    ("lg6", "lg6=0208|lgudp=aa3c13880208fcc2", "lg6=0209|lgudp=aa3c13880208fcc2"),
    ("lgudpcheck", "aa3c13880208fcc2", "aa3c13880208fcc3"),
    ("lgudplen", "aa3c13880208fcc2", "aa3c13880209fcc2"),
    ("lgplen", "lgplen=560|lg2=-1", "lgplen=561|lg2=-1"),
    ("lgp0", "lgp0=0081828384858687", "lgp0=0081828384858688"),
    ("ch", "exp=1|ch=1|ch0=1|agr=1", "exp=1|ch=2|ch0=1|agr=1"),
    ("agr", "ch=1|ch0=1|agr=1", "ch=1|ch0=1|agr=0"),
    ("rcvn", "att=1|n=1|n2=0", "att=1|n=2|n2=0"),
    ("rcvL", "L=512,0,0,0,0,0,-1,512", "L=512,0,0,0,0,0,-1,511"),
    ("rcvB", "B=0,0,0,0,0,0,-1,0", "B=1,0,0,0,0,0,-1,0"),
    ("rcvT", "|T=202,", "|T=902,"),
    ("wany", "wany=1|w520=1", "wany=2|w520=1"),
    ("udp", "udp=1|udperr=0", "udp=2|udperr=0"),
    ("udperr", "udp=4|udperr=0", "udp=4|udperr=1"),
    ("tapflen", "dev=y3b|k=0|flen=574", "dev=y3b|k=0|flen=575"),
    ("tapuhck", "uhlen=520|uhck=fcc2|stat=9", "uhlen=520|uhck=fcc3|stat=9"),
    ("tapstat", "uhck=fcc2|stat=9", "uhck=fcc2|stat=1"),
    ("taphop", "iplen=520|hop=63|uhlen=520", "iplen=520|hop=64|uhlen=520"),
    ("tappayload", "de66201f990802168244d6a186dd60", "de66201f990802168244d6a186dd61"),
    ("msg2", "lg2=12048", "lg2=12049"),
    ("win", "ND=66|WIN=700", "ND=66|WIN=600"),
    ("armname", "name=l_one_b", "name=l_one_x"),
    ("droparm", "DEL_ARM", ""),
]


def run(f1, f2):
    r = subprocess.run([sys.executable, V, f1, f2], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


ok = 0
bad = []
rc, out = run(R1, R2)
if rc != 0 or "Traceback" in out:
    bad.append("baseline is not green")
else:
    ok += 1
rc, out = run(R1, R2)
if rc != 0:
    bad.append("noop is not green")
else:
    ok += 1

base = open(R1, errors="replace").read()
for name, pat, rep in MUTS:
    if pat == "DEL_ARM":
        mut = "\n".join(l for l in base.split("\n")
                        if not l.startswith("F587 ARM|i=00|")) + "\n"
        if mut == base:
            bad.append("%s: pattern absent" % name)
            continue
    else:
        if pat not in base:
            bad.append("%s: pattern absent" % name)
            continue
        mut = base.replace(pat, rep)
        if mut == base:
            bad.append("%s: replacement did nothing" % name)
            continue
    os.makedirs(os.path.dirname(TMP), exist_ok=True)
    with open(TMP, "w") as f:
        f.write(mut)
    rc, out = run(TMP, R2)
    if "Traceback" in out:
        bad.append("%s: CRASH instead of a red verdict" % name)
    elif rc == 0:
        bad.append("%s: survived" % name)
    else:
        ok += 1

print("selftest: green_mutations=%d problems=%d" % (ok, len(bad)))
for b in bad:
    print("SELFTEST FAIL:", b)
sys.exit(1 if bad else 0)
