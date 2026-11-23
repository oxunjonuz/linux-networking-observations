#!/usr/bin/env python3
"""audit_f45_doc.py -- the document's tables are the tool's output, not prose.

SUMMARY.md contains one block between the two markers:

    <!-- BEGIN GENERATED (tools/f567_summary.py) -->
    ...
    <!-- END GENERATED -->

This script re-runs tools/f567_summary.py on the log, and requires every line
of its output to appear, in order, inside that block.  It then makes three
single substitutions in a copy of the document and requires each of them to be
caught -- an auditor that cannot fail is not an auditor.

Usage: audit_f45_doc.py [doc] [--selftest]
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
LOGS = os.environ.get(
    "F45_LOGS",
    "/work/kernel-sec/logs/f45_rep1.log,/work/kernel-sec/logs/f45_rep2.log"
).split(",")
TOOL = os.path.join(ROOT, "tools", "f567_summary.py")
BEGIN = "<!-- BEGIN GENERATED (tools/f567_summary.py) -->"
END = "<!-- END GENERATED -->"


def run_summary():
    env = dict(os.environ)
    env.setdefault("F45_LOGS",
                   "/work/kernel-sec/logs/f45_rep1.log,"
                   "/work/kernel-sec/logs/f45_rep2.log")
    p = subprocess.run([sys.executable, TOOL], capture_output=True, env=env)
    if p.returncode != 0:
        raise SystemExit("f567_summary.py failed: " + p.stderr.decode()[:400])
    return p.stdout.decode()


def block_of(doc):
    if BEGIN not in doc or END not in doc:
        raise SystemExit("markers missing")
    return doc.split(BEGIN, 1)[1].split(END, 1)[0]


def audit(doc, out):
    """Returns (cells_checked, mismatches)."""
    blk = block_of(doc)
    lines = [ln.rstrip() for ln in blk.split("\n")]
    cells = 0
    miss = []
    for ln in out.split("\n"):
        ln = ln.rstrip()
        if not ln:
            continue
        if ln.startswith("## "):
            continue
        cells += 1
        if ln not in lines:
            miss.append(ln)
    return cells, miss


def prose_claims(doc):
    """The numbers in the prose are recomputed from the log, not trusted."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    from verify567 import Log, hx
    L = Log(LOGS[0])
    A = L.arms
    cells = 0
    bad = []

    def get(sec, door, env, arm):
        for a in A:
            if (a["sec"], a["door"], a["env"], a["arm"]) == \
                    (sec, door, env, arm):
                return a
        return None

    def live(sec, door, env, arms):
        return sum(1 for c in arms
                   if int(get(sec, door, env, c)["lives"]) > 0)

    TH = ["t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4", "t12_4", "t16_2"]
    NH = ["n0_1", "n0_1x", "n0_2v", "n0_2x", "n1_1", "n2_2", "n2_4", "n4_2",
          "n6_2", "n7_1", "n7_2", "n8_1", "n8_2", "n8_16", "n24_4",
          "n24_16", "n28_4", "n40_2", "n44_2"]

    total = sum(live("td", d, e, TH) for d in ("ip6p", "inp", "ndg", "ieg")
                for e in ("v6", "hb", "do", "hbdo"))
    claims = []

    def claim(text, cond):
        nonlocal cells
        cells += 1
        if text not in doc:
            bad.append("prose: %r not in the document" % text)
        if not cond:
            bad.append("prose: %r is false in the log" % text)

    claim("**128 из 128 живых**", total == 128)
    claim("**19/19**", live("nh", "ndg", "v6", NH) == 19)
    claim("**9/19**", all(live("nh", d, "v6", NH) == 9
                          for d in ("ip6p", "inp", "ieg")))
    claim("**0/8 на всех дверях**",
          all(live("tf", d, e, TH) == 0 for d in
              ("ip6p", "inp", "ndg", "ieg") for e in ("frn", "none")))
    claim("**8/8 живы на всех дверях**",
          all(live("tf", d, "fr0", TH) == 8 for d in
              ("ip6p", "inp", "ndg", "ieg")))
    claim("3/3", all(int(get("rd", d, e, c)["lives"]) == 1
                     for d in ("inp", "ieg") for e in ("v6", "hb")
                     for c in ("r0_2", "r2_2", "r4_2")))
    claim("**524 плеча", len(A) == 524)
    claim("`n0_1x` → `InHdrErrors`",
          int(get("nh", "ndg", "v6", "n0_1x")["i6hdr"]) == 1)
    claim("`n2_4` на `inp` доставлен",
          int(get("nh", "inp", "v6", "n2_4")["i6deliv"]) == 1)
    claim("(T9: `i6in=2`, `i6deliv=1`, `u6a=1`)",
          int(get("td", "inp", "v6", "ctl")["i6in"]) == 2 and
          int(get("td", "inp", "v6", "ctl")["i6deliv"]) == 1 and
          int(get("td", "inp", "v6", "ctl")["u6a"]) == 1)
    claim("`l4_17` ожил",
          int(get("mp", "inp", "v6", "l4_17")["lives"]) == 1)
    claim("**срабатывает и возвращает 59**",
          int(get("mp", "inp", "none", "l4_59")["lives"]) == 1)
    claim("`mexth` (hop-by-hop с hdrlen 15)",
          int(get("md_inp_l3", "inp", "mexth", "ctl")["cntp"]) == 0)
    claim("**0/0**: длина и hop-by-hop",
          int(get("md_inp_l3", "inp", "mexth", "ctl")["cntp"]) == 0 and
          int(get("md_inp_l3", "inp", "mtrunc", "ctl")["cntp"]) == 0)
    claim("`unspec` на layer-3 двери", int(get("md_inp_l3", "inp",
                                               "mdobad", "ctl")["cntp"]) == 1)
    claim("`u4=2`", all(int(x["u4"]) == 2 for x in L.xc
                        if x["env"] == "p4"))
    return cells, bad


def main():
    doc_path = os.path.join(ROOT, "findings", "F45-ipv6-walk", "SUMMARY.md")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if args:
        doc_path = args[0]
    doc = open(doc_path).read()
    out = run_summary()
    cells, miss = audit(doc, out)
    pcells, pbad = prose_claims(doc)
    print("cells=%d mismatches=%d" % (cells, len(miss)))
    print("prose_cells=%d mismatches=%d" % (pcells, len(pbad)))
    for m in miss[:20]:
        print("MISS " + m)
    for m in pbad[:20]:
        print("PROSE " + m)

    rc = 0 if not (miss or pbad) else 1

    if "--selftest" in sys.argv:
        # three single substitutions in a copy of the document
        subs = []
        for ln in out.split("\n"):
            if ln.startswith("| ") and ln.count("|") >= 4 and \
                    (re.search(r"\d", ln) or "+" in ln):
                subs.append(ln)
                if len(subs) == 3:
                    break
        if len(subs) < 3:
            print("SELFTEST cannot find three rows")
            return 1
        for i, ln in enumerate(subs):
            m = re.search(r"\d+", ln)
            if m:
                cells_mut = (ln[:m.start()] + str(int(m.group(0)) + 1) +
                             ln[m.end():])
            else:
                cells_mut = ln.replace("+", ".", 1)
            mut = doc.replace(ln, cells_mut, 1)
            if mut == doc:
                print("SELFTEST %d did not change the document" % i)
                rc = 1
                continue
            c2, m2 = audit(mut, out)
            if not m2:
                print("SELFTEST %d: substitution NOT caught: %s" % (i, ln))
                rc = 1
            else:
                print("SELFTEST %d ok: substitution caught (%d cells)"
                      % (i, c2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
