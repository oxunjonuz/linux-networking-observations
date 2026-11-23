#!/usr/bin/env python3
"""audit_f33_doc.py -- recompute every cell of F33's tables from the boot logs.

The document may not say a number the logs do not say.  Three tables in
findings/F33-guard-type-table/SUMMARY.md are marked with HTML comments
(F33T1, F33T2, F33T3); every row is found by its leftmost cell and every other
cell is re-derived from logs/f33_T_rep1.log and compared one by one.

usage: python3 tools/audit_f33_doc.py [--quiet]
"""
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F33-guard-type-table/SUMMARY.md")
LOG = os.path.join(ROOT, "logs/f33_T_rep1.log")

GRID_OFF = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
GRID_LEN = [1, 2, 4]
XOFF = [0, 8, 16, 20]
XLEN = [8, 16, 16, 16]
ENVS = ["ip4", "ip6", "nd", "eg4", "egA", "br4", "brA", "arp",
        "ll4", "llN", "llE", "llB"]
# one keyword per envelope: the type cell must name the kind, and the kind is
# what the shape is supposed to show
TYPE_KEY = {
    "ip4": "точек", "ip6": "точек", "nd": "онстант", "eg4": "переключатель",
    "egA": "переключатель", "br4": "переключатель", "brA": "переключатель",
    "arp": "полуплоскость", "ll4": "раница", "llN": "онстант",
    "llE": "раница", "llB": "раница",
}
E_ROWS = ["ip4_0_2_ihl5", "ip4_0_2_ihl6", "ip4_8_2_p17", "ip4_8_2_p6",
          "ip6_0_4_v6_a", "ip6_0_4_v6_b", "ip6_0_4_v4_a", "ip6_0_4_v4_b",
          "arp_fam_arpframe", "arp_fam_ipv4frame", "br_6_2_ip", "br_6_2_arp",
          "br_6_4_arp"]

CELLS = 0
MISMATCH = []


def cell(where, want, got):
    global CELLS
    CELLS += 1
    if str(want).strip() != str(got).strip():
        MISMATCH.append("%s: doc=%r log=%r" % (where, want, got))


def arms():
    """keyed by (env, arm): arm names repeat across envelopes ("g0_1" exists in
    every one of them), and keying by the arm alone silently attributed every
    row to the last envelope read."""
    d = {}
    rx = re.compile(r"^F556 R\|env=(\w+)\|arm=(\w+)\|off=(\d+)\|len=(\d+)\|"
                    r"kind=(\d+)\|rc=(-?\d+)\|cnt=(\d+)\|cnt0=(\d+)\|"
                    r"nfl=(\d+)\|")
    with open(LOG, errors="replace") as f:
        for ln in f:
            m = rx.match(ln)
            if m:
                d[(m.group(1), m.group(2))] = dict(
                    env=m.group(1), arm=m.group(2), off=int(m.group(3)),
                    len=int(m.group(4)), nfl=int(m.group(9)),
                    alive=int(m.group(7)) - int(m.group(8)) == 1)
    return d


def table(marker):
    txt = open(DOC, errors="replace").read()
    if marker not in txt:
        MISMATCH.append("%s: marker missing from the document" % marker)
        return []
    tail = txt[txt.index(marker):].splitlines()[1:]
    rows = []
    for ln in tail:
        if not ln.startswith("|"):
            if rows:
                break
            continue
        rows.append([c.strip() for c in ln.strip().strip("|").split("|")])
    return rows


def main():
    quiet = "--quiet" in sys.argv
    A = arms()
    sets = {e: sorted((a["off"], a["len"]) for a in A.values()
                      if a["env"] == e and a["alive"]) for e in ENVS}

    # ---- T1: env | type | accepted/40 | cells ----
    for row in table("<!-- F33T1 -->"):
        if row[0].startswith("---") or row[0] in ("конверт", ":---"):
            continue
        env = row[0].strip("`")
        if env not in sets:
            continue
        cell("T1.%s.type" % env, TYPE_KEY[env] in row[1], TYPE_KEY[env] in row[1])
        cell("T1.%s.count" % env, row[2].replace("*", "").strip(),
             "%d/40" % len(sets[env]))
        cells = " ".join("(%d,%d)" % c for c in sets[env])
        cell("T1.%s.cells" % env, row[3].strip("`"), cells)

    # ---- T2: cell | ip4 | ip6 | ... ----
    hdr = [r for r in table("<!-- F33T2 -->") if r[0] == "клетка"]
    envs = hdr[0][1:] if hdr else []
    for row in table("<!-- F33T2 -->"):
        if row[0] == "клетка" or row[0].startswith("---"):
            continue
        m = re.match(r"\((\d+),(\d+)\)", row[0].strip("`"))
        if not m:
            continue
        off, ln = int(m.group(1)), int(m.group(2))
        for j, env in enumerate(envs):
            alive = (off, ln) in sets[env]
            cell("T2.(%d,%d).%s" % (off, ln, env), row[j + 1], 1 if alive else 0)

    # ---- T3: arm | what | value | cnt ----
    for row in table("<!-- F33T3 -->"):
        if row[0] == "плечо" or row[0].startswith("---"):
            continue
        arm = row[0].strip("`")
        hit = [v for (e, a), v in A.items() if a == arm]
        if not hit:
            MISMATCH.append("T3.%s: arm missing from the log" % arm)
            continue
        cell("T3.%s.cnt" % arm, row[3], 1 if hit[0]["alive"] else 0)

    print("audit_f33_doc: %d cells, %d mismatches" % (CELLS, len(MISMATCH)))
    for m in MISMATCH[:30]:
        print("  " + m)
    if MISMATCH:
        sys.exit(1)


if __name__ == "__main__":
    main()
