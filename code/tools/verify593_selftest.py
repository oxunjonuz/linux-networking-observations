#!/usr/bin/env python3
"""verify593_selftest.py -- can verify593.py go RED?

A check that cannot fail is not a check (F70 #5, F68: the surviving
`half-inclusive` mutation, F50 #5).  This takes a copy of the log, changes ONE
thing in it, and requires the verifier to exit non-zero WITHOUT a traceback.
A `noop` control must stay green, and a missing log must be refused cleanly.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
SRC = ROOT + "/logs/f71_rep1.log"
VER = ROOT + "/tools/verify593.py"

MUT = [
    ("pull-count", lambda t: t.replace(
        "F593 CNT|i=02|att=0|enq=1|cond=1|pull=1|seg=0|trim=0|clone=0|"
        "exp=0|eat=147|mark=1",
        "F593 CNT|i=02|att=0|enq=1|cond=1|pull=0|seg=0|trim=0|clone=0|"
        "exp=0|eat=147|mark=1", 1)),
    ("eat-by-one", lambda t: t.replace("exp=0|eat=147|mark=1",
                                       "exp=0|eat=146|mark=1", 1)),
    ("branch-dlen", lambda t: re.sub(
        r"(F593 CQ\|i=02\|att=0\|n=1\|ts=2240\|dlen=)147", r"\g<1>146", t, 1)),
    ("branch-cloned", lambda t: re.sub(
        r"(F593 CQ\|i=02\|att=0\|n=1\|ts=2240\|dlen=147\|len=659\|tail=556\|"
        r"end=704\|fl=)0", r"\g<1>1", t, 1)),
    ("charge", lambda t: t.replace(
        "F593 RCV|i=02|att=0|n0=0|n1=17|rmem0=0|rmem1=21760",
        "F593 RCV|i=02|att=0|n0=0|n1=17|rmem0=0|rmem1=22720", 1)),
    ("probe-offsets", lambda t: t.replace(
        "off=112,116,188,192,216,126", "off=112,116,188,192,216,127", 1)),
    ("initrd-sha", lambda t: re.sub(r"(### initrd sha256: )([0-9a-f])",
                                    lambda m: m.group(1) +
                                    ("0" if m.group(2) != "0" else "1"), t, 1)),
    ("enqueue-count", lambda t: t.replace(
        "F593 CNT|i=00|att=0|enq=1|cond=0", "F593 CNT|i=00|att=0|enq=2|cond=0",
        1)),
    ("arm-name", lambda t: t.replace(
        "F593 ARM|i=07|att=0|name=g_t200_139", "F593 ARM|i=07|att=0|name=g_t200_140",
        1)),
    ("gate-truesize", lambda t: re.sub(
        r"(F593 EQ\|i=07\|att=0\|n=1\|ts=)1920", r"\g<1>1921", t, 1)),
    ("delivered-length", lambda t: t.replace(
        "hl0=-1,-1|hl1=512,660|udpin=104", "hl0=-1,-1|hl1=512,661|udpin=104", 1)),
    ("mark", lambda t: t.replace(
        "F593 CNT|i=03|att=0|enq=1|cond=1|pull=1|seg=0|trim=0|clone=0|"
        "exp=0|eat=148|mark=1",
        "F593 CNT|i=03|att=0|enq=1|cond=1|pull=1|seg=0|trim=0|clone=0|"
        "exp=0|eat=148|mark=0", 1)),
    ("udpin", lambda t: re.sub(r"(\|udpin=)155(\|udperr=0)", r"\g<1>156\g<2>",
                               t, 1)),
    ("drop-attempt", lambda t: re.sub(
        r"F593 ARM\|i=17\|att=1\|.*?(?=F593 ARM\||\Z)", "", t, 1, re.S)),
    ("wait-ok", lambda t: t.replace("want=20480|rmem=20480", "want=20480|rmem=20480",
                                    1).replace("stable=100|ok=1", "stable=100|ok=0", 1)),
    ("boundary-returns", lambda t: t.replace(
        "F593 CNT|i=04|att=0|enq=1|cond=1|pull=0|seg=0|trim=0|clone=0|"
        "exp=0|eat=-1|mark=1",
        "F593 CNT|i=04|att=0|enq=1|cond=1|pull=1|seg=0|trim=0|clone=0|"
        "exp=0|eat=149|mark=1", 1)),
    ("tap-not-cloned", lambda t: re.sub(
        r"(F593 CQ\|i=05\|att=0\|n=1\|ts=2240\|dlen=147\|len=659\|tail=556\|"
        r"end=704\|fl=)1", r"\g<1>0", t, 1)),
    ("trim-nonzero", lambda t: t.replace(
        "F593 CNT|i=13|att=0|enq=6|cond=6|pull=0|seg=1|trim=0",
        "F593 CNT|i=13|att=0|enq=6|cond=6|pull=0|seg=1|trim=1", 1)),
]


def run(path):
    p = subprocess.run([sys.executable, VER, path], capture_output=True,
                       text=True)
    return p.returncode, p.stdout + p.stderr


def main():
    base = open(SRC, "r", errors="replace").read()
    tmp = tempfile.mkdtemp(prefix="v593st")
    ok = 0
    bad = 0
    # 1. noop: the untouched copy must stay green
    p0 = os.path.join(tmp, "noop.log")
    open(p0, "w").write(base)
    rc, out = run(p0)
    if rc == 0:
        ok += 1
        print("noop                    green  (as required)")
    else:
        bad += 1
        print("noop                    RED    <-- the copy is not a copy")
        print(out[-1500:])
    # 2. one mutation at a time
    for name, fn in MUT:
        txt = fn(base)
        if txt == base:
            bad += 1
            print("%-22s SAMPLE NOT FOUND" % name)
            continue
        p = os.path.join(tmp, name + ".log")
        open(p, "w").write(txt)
        rc, out = run(p)
        tb = "Traceback (most recent call last)" in out
        if rc != 0 and not tb:
            ok += 1
            print("%-22s red    (rc=%d)" % (name, rc))
        elif tb:
            bad += 1
            print("%-22s TRACEBACK <-- the verifier must go red, not crash"
                  % name)
            print(out[-800:])
        else:
            bad += 1
            print("%-22s SURVIVED <-- a hole in the verifier" % name)
    # 3. a missing log must be refused, not crash
    rc, out = run(os.path.join(tmp, "does-not-exist.log"))
    tb = "Traceback (most recent call last)" in out
    if rc != 0 and not tb:
        ok += 1
        print("missing-log            refused (rc=%d)" % rc)
    else:
        bad += 1
        print("missing-log            %s" % ("TRACEBACK" if tb else "GREEN"))
    print("SELFTEST %d/%d" % (ok, ok + bad))
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
