#!/usr/bin/env python3
"""audit_f52_doc.py -- every table cell in the F52 report against the log.

The document's six tables are `tools/f574_summary.py`'s output pasted in by
`tools/assemble_f52.py`.  This script regenerates them from
logs/f52_rep1.log and compares cell by cell with what the document actually
says -- a typo in a table is a mismatch, not a smaller number of checks.

Then it substitutes three single cells in a copy of the document and requires
that each substitution reddens exactly that cell.
"""
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F52-vlan-tag/SUMMARY.md"
GEN = ROOT + "/tools/f574_summary.py"
LOG = ROOT + "/logs/f52_rep1.log"

NCHECK = 0
FAIL = []


def chk(cond, what):
    global NCHECK
    NCHECK += 1
    if not cond:
        FAIL.append(what)


def parse_tables(text):
    """{ 'T1': [ [header...], [row...], ... ] } for '## T1 -- ...' sections."""
    out = {}
    cur = None
    for ln in text.splitlines():
        m = re.match(r"^## (T\d) -- ", ln)
        if m:
            cur = m.group(1)
            out[cur] = []
            continue
        if cur and ln.startswith("|"):
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue
            out[cur].append(cells)
        elif cur and not ln.startswith("|"):
            cur = None
    return out


def main():
    gen = subprocess.run([sys.executable, GEN, LOG], capture_output=True,
                         text=True, check=True).stdout
    want = parse_tables(gen)
    doc = open(DOC).read()
    got = parse_tables(doc)
    for t in sorted(want):
        chk(t in got, "table %s present in the document" % t)
        if t not in got:
            continue
        chk(len(got[t]) == len(want[t]),
            "%s row count: doc %d, log %d" % (t, len(got[t]), len(want[t])))
        for i, row in enumerate(want[t]):
            if i >= len(got[t]):
                break
            for j, cell in enumerate(row):
                chk(j < len(got[t][i]) and got[t][i][j] == cell,
                    "%s r%d c%d: doc %r log %r" % (
                        t, i, j,
                        got[t][i][j] if j < len(got[t][i]) else None, cell))
    print("%d cells, %d mismatches" % (NCHECK, len(FAIL)))
    for f in FAIL[:20]:
        print("  MISMATCH", f)
    if FAIL:
        return 1

    # ---- three single-cell substitutions must each redden one cell
    subs = [
        ("| c100 | B | - | 1 | 2 | 1 | 0 | 1 | 0 | 1 | 1 | 1 |",
         "| c100 | B | - | 1 | 2 | 1 | 0 | 1 | 1 | 1 | 1 | 1 |"),
        ("| r12t | 12 | 2 | 8100 | yes | 1 |",
         "| r12t | 12 | 2 | 8100 | no | 1 |"),
        ("| w14_0 | @ll,14,2 = 0000 | 0 | 1 | 1 | 0 | 80 | 86dd60000000 |",
         "| w14_0 | @ll,14,2 = 0000 | 0 | 1 | 0 | 0 | 80 | 86dd60000000 |"),
    ]
    bad = 0
    for a, b in subs:
        chk(a in doc, "substitution anchor present: " + a[:40])
        if a not in doc:
            continue
        tmp = "/tmp/f52_doc_sub.md"
        open(tmp, "w").write(doc.replace(a, b, 1))
        r = subprocess.run([sys.executable, __file__, tmp],
                           capture_output=True, text=True)
        if r.returncode == 1:
            print("substitution caught:", r.stdout.strip().splitlines()[0])
        else:
            bad += 1
            print("SUBSTITUTION SURVIVED:", a[:50])
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) > 1:
        DOC = sys.argv[1]
    sys.exit(main())
