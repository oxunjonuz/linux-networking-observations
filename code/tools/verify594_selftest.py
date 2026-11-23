#!/usr/bin/env python3
"""verify594_selftest.py -- can verify594.py go red?

Two kinds of mutation, because they prove different things:

  model   one line of the verifier's model is changed (a constant, an
          inequality, a branch); the real logs must make it go red.
  data    one field of a COPY of the log is changed (an enqueue record, a
          packet count, a charge, a marker, a copy count, the kernel sha ...);
          the verifier must notice -- this is what makes a check load-bearing
          rather than merely present.  verify594.py reads F72_LOG1/F72_LOG2
          for exactly this.

A mutation is caught when the exit code is non-zero AND there is no traceback.
The no-op copy must stay green.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
VER = os.path.join(ROOT, "tools", "verify594.py")
LOG1 = os.path.join(ROOT, "logs", "f72_rep1.log")
LOG2 = os.path.join(ROOT, "logs", "f72_rep2.log")

MODEL = [
    ("noop", "", ""),
    ("truesize-constant", "end + 576 +", "end + 577 +"),
    ("truesize-condense", "recs[0][4] + 576", "recs[0][4] + 320"),
    ("page-align-off", "return (n + 4095) & ~4095", "return n"),
    ("page-align-never", "page_align(dlen) if dlen > 0 else 0", "0"),
    ("page-align-half", "return (n + 4095) & ~4095", "return (n + 2047) & ~2047"),
    ("rule-merges-zcopy", 'if a["zc"] and a["xg"] == "u":\n        return False',
     'if a["zc"] and a["xg"] == "u":\n        return True'),
    ("rule-one-packet", "return 1, [8 + sum(ps)]", "return len(ps), [8 + p for p in ps]"),
    ("kept-plus-one", 'int(rcv["rb%d" % port]) // s',
     'int(rcv["rb%d" % port]) // s + 1'),
    ("kept-minus-one", 'int(rcv["rb%d" % port]) // s',
     'max(0, int(rcv["rb%d" % port]) // s - 1)'),
    ("clause2-egr-charge", '"c_egr": (0, 2240, 1)', '"c_egr": (0, 1280, 1)'),
    ("clause2-ingd-bit", '"c_ing_d": (1, 1280, 0)', '"c_ing_d": (1, 1280, 1)'),
    ("len-identity", 'ck("E", ln == (tail - 44) + dlen,',
     'ck("E", ln == (tail - 44) + dlen + 1,'),
    ("end-model", 'end = 704 if (not a["zc"] and p > 148) else 384',
     'end = 704 if p > 148 else 384'),
    ("ubuf-linear", 'ck("G", ubuf == t["n"],', 'ck("G", ubuf == 0,'),
    ("ubuf-fraglist", 'ck("G", ubuf == 1,', 'ck("G", ubuf == 0,'),
    ("seg-fraglist", 'ck("G", seg == 1,', 'ck("G", seg == 0,'),
    ("arm-count", 'ck("C", len(order) == 2 * 13,', 'ck("C", len(order) == 2 * 12,'),
    ("anchor-missing", '("net/core/gro.c", "p->truesize += skb->truesize;"),',
     '("net/core/gro.c", "this line does not exist anywhere;"),'),
    ("short-tail", 'if a["sh"] >= 0:\n        out[a["sh"]] = a["sl"]',
     'if a["sh"] >= 0:\n        pass'),
    ("queue-model", "want = sum(r[0] for r in recs)",
     "want = sum(r[0] for r in recs) + 1"),
    ("payload-rule", "return len(ps), [8 + p for p in ps]",
     "return len(ps), [8 + p + 1 for p in ps]"),
    ("received-model", 'base_recv = t["j"] + (1 if whole else t["n"])',
     'base_recv = t["j"] + 1'),
    ("whole-model", 'whole = (npr == 1 and t["n"] > 1 and t["skt"] == "g")',
     'whole = False'),
    ("charge-vs-end", '(charged == end0 + 576) == (w_pull == 1)',
     '(charged == end0 + 576) == (w_pull == w_pull)'),
]

# (name, regex on one line, replacement, which log)
DATA = [
    ("ts-field", r"(F594 EQ\|i=01\|att=0\|n=6\|ts=)5056", r"\g<1>5057", 1),
    ("dlen-field", r"(F594 EQ\|i=01\|att=0\|n=6\|ts=[0-9,]+\|dlen=)512", r"\g<1>511", 1),
    ("enq-count", r"(F594 CNT\|i=01\|att=0\|enq=)6", r"\g<1>5", 1),
    ("ubuf-count", r"(F594 CNT\|i=01\|att=0\|.*\|ubuf=)6", r"\g<1>5", 1),
    ("seg-count", r"(F594 CNT\|i=04\|att=0\|.*\|seg=)1", r"\g<1>0", 1),
    ("pull-count", r"(F594 CNT\|i=09\|att=0\|.*\|pull=)1", r"\g<1>0", 1),
    ("mark-flag", r"(F594 CNT\|i=00\|att=0\|.*\|mark=)1", r"\g<1>0", 1),
    ("uhlen", r"(F594 PKT\|i=01\|att=0\|n=6\|uhlen=)520", r"\g<1>521", 1),
    ("pkt-count", r"(F594 PKT\|i=01\|att=0\|n=)6", r"\g<1>5", 1),
    ("charge-rmem", r"(F594 RCV\|i=01\|att=0\|.*\|rmem0=)30336", r"\g<1>30337", 1),
    ("received", r"(F594 RCV\|i=01\|att=0\|n0=)6", r"\g<1>5", 1),
    ("sent", r"(F594 ZC\|sent=)6(\|zc=1)", r"\g<1>5\g<2>", 1),
    ("kernel-sha", r"(### sha256: )1efbc957", r"\g<1>0efbc957", 1),
    ("arm-pl", r"(\|name=z_lin6\|.*\|pl=)512", r"\g<1>513", 1),
    ("fl-bit", r"(F594 EQ\|i=10\|att=0\|n=1\|ts=2240\|dlen=148\|len=660\|tail=556\|end=704\|fl=)1",
     r"\g<1>0", 1),
    ("second-boot", r"(F594 PKT\|i=01\|att=1\|n=)6", r"\g<1>7", 2),
]


def run(ver, log1, log2):
    env = dict(os.environ)
    env["F72_LOG1"] = log1
    env["F72_LOG2"] = log2
    p = subprocess.run([sys.executable, ver], capture_output=True, text=True, env=env)
    return p.returncode, p.stdout + p.stderr


def main():
    src = open(VER).read()
    base1 = open(LOG1, "rb").read().decode("utf-8", "replace")
    base2 = open(LOG2, "rb").read().decode("utf-8", "replace")
    tmp = tempfile.mkdtemp(prefix="f72st_")
    ok = 0
    bad = []
    total = len(MODEL) + len(DATA)

    for name, old, new in MODEL:
        s = src
        if old:
            if old not in s:
                bad.append("%s: SAMPLE NOT FOUND" % name)
                continue
            s = s.replace(old, new, 1)
        path = os.path.join(tmp, "v_%s.py" % name)
        with open(path, "w") as f:
            f.write(s)
        rc, out = run(path, LOG1, LOG2)
        crashed = "Traceback (most recent call last)" in out
        if name == "noop":
            if rc == 0:
                ok += 1
                print("model  %-20s green as it must be" % name)
            else:
                bad.append("noop: the baseline is red")
            continue
        if rc != 0 and not crashed:
            ok += 1
            print("model  %-20s red   %s" % (name, [l for l in out.split("\n") if l.startswith("FAIL ")][:1]))
        else:
            bad.append("%s: %s" % (name, "crashed" if crashed else "SURVIVED"))

    for name, pat, rep, which in DATA:
        base = base1 if which == 1 else base2
        new_log, n = re.subn(pat, rep, base, count=1)
        if n != 1:
            bad.append("data %s: SAMPLE NOT FOUND" % name)
            continue
        l1 = os.path.join(tmp, "l1_%s.log" % name)
        l2 = os.path.join(tmp, "l2_%s.log" % name)
        if which == 1:
            open(l1, "w").write(new_log)
            open(l2, "w").write(base2)
        else:
            open(l1, "w").write(base1)
            open(l2, "w").write(new_log)
        rc, out = run(VER, l1, l2)
        crashed = "Traceback (most recent call last)" in out
        if rc != 0 and not crashed:
            ok += 1
            print("data   %-20s red   %s" % (name, [l for l in out.split("\n") if l.startswith("FAIL ")][:1]))
        else:
            bad.append("data %s: %s" % (name, "crashed" if crashed else "SURVIVED"))

    shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d/%d  %s" % (ok, total, "ALL OK" if not bad else "BAD: " + "; ".join(bad)))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
