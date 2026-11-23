#!/usr/bin/env python3
"""audit_f59_doc.py -- does the document say what the log says?

Two independent paths:

  A. Every table row of findings/F59-three-guards/SUMMARY.md whose first cell is
     an arm name (or a frame name) must appear IDENTICALLY in the table that
     tools/f59_summary.py regenerates from logs/f59_rep1.log -- and vice versa,
     so the document cannot add, drop or quietly edit a row.
  B. The prose numbers that the tables cannot carry are re-derived: the arm
     count from summary.json, the check count from verify581.py's own output,
     the selftest round count from f581_mutate.py --list, and the refuted
     prediction list from research/predictions_581.md.

Usage: python3 tools/audit_f59_doc.py [--doc PATH] [-q]
Exit 0 iff every cell agrees.
"""

import collections
import json
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F59-three-guards/SUMMARY.md")
SUM = os.path.join(ROOT, "findings/F59-three-guards/summary.json")
GEN = os.path.join(ROOT, "tools/f59_summary.py")
VER = os.path.join(ROOT, "tools/verify581.py")
MUT = os.path.join(ROOT, "tools/f581_mutate.py")
PRED = os.path.join(ROOT, "research/predictions_581.md")

BAD = []
N = [0]


def ck(cond, what, extra=""):
    N[0] += 1
    if not cond:
        BAD.append("%s %s" % (what, extra))


NORM = {"да": "1", "yes": "1", "нет": "0", "no": "0", "—": "-",
        "netdev": "0", "inet": "1", "@ll": "0", "@nh": "1", "@th": "2",
        "есть": "inet_present", "удалена": "inet_removed",
        "F1": "1", "F2": "2", "F3": "3"}


def norm(c):
    c = c.replace("**", "").replace("`", "").strip()
    return NORM.get(c, c)


def table_rows(text, known):
    """(first cell, occurrence index) -> normalised cells, for known rows."""
    rows = {}
    seen = collections.Counter()
    for line in text.splitlines():
        if not line.startswith("| ") or line.startswith("| ---"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        cells[0] = cells[0].replace("**", "").split()[0] if cells[0] else ""
        if cells[0] not in known:
            continue
        key = (cells[0], seen[cells[0]])
        seen[cells[0]] += 1
        rows[key] = [norm(c) for c in cells]
    return rows


def main():
    doc_path = DOC
    args = sys.argv[1:]
    if args and args[0] == "--doc":
        doc_path = args[1]
    doc = open(doc_path, encoding="utf-8").read()
    summary = json.load(open(SUM))
    names = set(r["name"] for r in summary["rows"]) | {"F5", "F6"}
    ck(len(names) == 65, "arm names in summary.json", str(len(names)))

    # A. the tables
    out = subprocess.run([sys.executable, GEN, "logs/f59_rep1.log", "--no-write"],
                         cwd=ROOT,
                         capture_output=True, text=True)
    ck(out.returncode == 0, "f59_summary.py runs", out.stderr[-200:])
    gen = table_rows(out.stdout, names)
    got = table_rows(doc, names)
    genrows = collections.Counter(tuple(v) for v in gen.values())
    docrows = collections.Counter(tuple(v) for v in got.values())
    for row, n in genrows.items():
        ck(docrows.get(row, 0) >= n, "row present in the document", " | ".join(row))
    # rows that exist only in the document (the small summary tables of §5.2 and
    # §6): every cell must still be a value the log has for that arm
    pool = collections.defaultdict(set)
    for v in gen.values():
        pool[v[0]] |= set(v)
    extra = 0
    for row, n in docrows.items():
        if genrows.get(row, 0) >= n:
            continue
        extra += 1
        for c in row[1:]:
            if re.fullmatch(r"-?\d+", c) or c.count(":") >= 2 or \
                    c in ("-", "inet_present", "inet_removed"):
                ck(c in pool[row[0]], "extra row %s numeric cell" % row[0],
                   repr(c))
    ck(extra <= 6, "document has at most six rows beyond the generated tables",
       str(extra))

    # B. the prose
    arms = summary["arms"]
    ck(("%d плеча" % arms) in doc, "prose: arm count %d" % arms)
    ck(("63 плеча" in doc) == (arms == 63), "prose: 63 arms consistent")

    v = subprocess.run([sys.executable, VER], cwd=ROOT, capture_output=True,
                       text=True)
    m = re.search(r"checks=(\d+) fails=(\d+)", v.stdout)
    ck(m is not None, "verify581.py prints its count")
    if m:
        ck(int(m.group(2)) == 0, "verify581.py is green", m.group(0))
        ck(("%s проверок" % m.group(1)) in doc,
           "prose: check count %s" % m.group(1))
    rounds = len(subprocess.run([sys.executable, MUT, "--list"], cwd=ROOT,
                                capture_output=True, text=True).stdout.split())
    ck(("%d/%d" % (rounds, rounds)) in doc,
       "prose: selftest %d/%d" % (rounds, rounds))
    ck(("%d односоставны" % (rounds - 1)) in doc or
       ("%d одиночны" % (rounds - 1)) in doc,
       "prose: %d single-field mutations" % (rounds - 1))

    pred = open(PRED, encoding="utf-8").read()
    ck(len(re.findall(r"^P\d+\.", pred, re.M)) == 15, "predictions file has P1..P15")
    ck("P13 (первая клауза)" not in doc, "prose: P13 counted once")
    ck("P7 опровергнуто" in doc, "prose: P7 refutation recorded")

    # a few numbers the tables carry only in prose
    by = {r["name"]: r for r in summary["rows"]}
    ck(by["n1_ll14"]["rcv"] == "0" and by["n1_ll14"]["hdrerr"] == "1",
       "n1_ll14 dies before ip6_rcv_core")
    ck(by["i1_ll14"]["nl"] == "0", "i1_ll14 refused")
    ck(by["a_8_6"]["arp11"] == "a0:a1:a2:a3:a4:a5", "a_8_6 learned MAC")
    ck(by["v4_u0_cs"]["u4err"] == "1", "v4_u0_cs killed by its own fixup")
    ck(by["v4_u0_fl"]["u4n"] == "1", "v4_u0_fl skipped, delivered")
    ck(by["v6_s_cs"]["udperr6"] == "1", "v6_s_cs silent no-op")
    ck(by["i1_ttl_cs"]["u4n"] == "1" and by["i1_ttl_no"]["iphdr"] == "1",
       "the ingress pair")
    ck(sum(1 for r in summary["rows"] if r["rc"] != "0") == 3,
       "three load-time refusals")
    ck(sum(1 for r in summary["rows"]
           if r["store"] == "1" and r["rc"] == "0" and r["nl"] == "0") == 15,
       "fifteen guard refusals")

    print("checks=%d fails=%d" % (N[0], len(BAD)))
    for b in BAD[:40]:
        print("  FAIL " + b)
    return 1 if BAD else 0


if __name__ == "__main__":
    sys.exit(main())
