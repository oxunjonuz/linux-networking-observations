#!/usr/bin/env python3
"""audit_f54_doc.py -- do the numbers in SUMMARY.md exist in the log?

Renders the four tables of findings/F54-tag-on-the-wire/SUMMARY.md from
logs/f54_rep1.log (sections 3, 4, 7 and the door table of 2) and requires every
rendered row to appear verbatim in the document.  Then does the same on a copy
of the document with one cell changed, which must fail -- otherwise the audit
is not looking.

usage: audit_f54_doc.py [mutate]
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import verify576 as V

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F54-tag-on-the-wire/SUMMARY.md")


def tables(log="logs/f54_rep1.log"):
    V.ARMS, _ = V.parse_arms_from_source()
    head, arms, frms, env, wtot, lines = V.parse_log(os.path.join(ROOT, log))
    xf = arms["xf"]
    wa = arms["warn"]
    t3, t4, t7 = [], [], []
    for a in xf:
        c = a["raw_c2"]
        name = a["arm"]
        acts = V.ARMS[name]
        a1 = ("read `@ll,%d,%d` == %04x at `%s`" % (acts[0][2], acts[0][3],
                                                   int(acts[0][4], 16),
                                                   acts[0][0])
              if acts and acts[0][1] == 3 else
              ("store %04x at `%s`" % (int(acts[0][4], 16), acts[0][0])
               if acts else None))
        a2 = ("%04x at `%s`" % (int(acts[1][4], 16), acts[1][0])
              if len(acts) > 1 else None)
        if name in ("rd_g6_65", "e1_rd_tpid"):
            t3.append("| `%s` | %s | — | **%s** | — |" % (name, a1, c["ch0"]))
        elif name.startswith("w67") or name in ("same66_f6_rd_e0",
                                                "pc1_f6_rd_e0_66"):
            t3.append("| `%s` | %s | %s | **%s** | **%s** |" %
                      (name, a1, a2, c["ch0"], c["ch1"]))
        f = a["f"]
        tap = a["tap"]["t0"]
        tapc = "%d · %s" % (tap["n"], tap["flen"] if tap["flen"] > 0 else "—")
        t4.append("| `%s` | %s | %s | %s | %s | %s | %s |" % (
            name, f["v101p_d"],
            "**1**" if f["v102p_d"] == "1" else "0",
            f["v102b_d"], f["x0rxb_d"],
            "**1**" if f["x1oth_d"] == "1" else "0", tapc))
    for a in wa:
        w = a["w"]
        t7.append("| `%s` | %s | %s | %s | **%s** | %s | %s |" % (
            a["arm"], {"w_ctl": "none", "w_tag": "store 0806 at 12,2",
                       "w_tag_x3": "store 0806 at 12,2",
                       "w_untag": "store 0806 at 12,2",
                       "w_same": "store 8100 at 12,2"}[a["arm"]],
            {"w_ctl": "1 tagged", "w_tag": "1 tagged", "w_tag_x3": "3 tagged",
             "w_untag": "1 untagged", "w_same": "1 tagged"}[a["arm"]],
            w["ch"] if w["ch"] != "0" else "0", w["dspl"],
            "**1**" if w["v111p_d"] == "1" else "0",
            "**%s**" % w["x1oth_d"] if w["x1oth_d"] != "0" else "0"))
    return t3, t4, t7


def check(doc_text, rows_all):
    bad = 0
    n = 0
    for rows in rows_all:
        for r in rows:
            n += 1
            if r not in doc_text:
                bad += 1
                print("MISSING ROW: " + r)
    return n, bad


def main():
    rows = tables()
    doc = open(DOC).read()
    n, bad = check(doc, rows)
    if bad:
        print("AUDIT FAIL %d of %d rows" % (bad, n))
        return 1
    print("AUDIT OK %d rows, %d cells" %
          (n, sum(r.count("|") - 1 for rows_ in rows for r in rows_)))
    if len(sys.argv) > 1 and sys.argv[1] == "mutate":
        subs = [("| `pc1_f6_rd_e0_66` | store 2065 at `f6` | 0066 at `e0` | "
                 "**1** | **1** |",
                 "| `pc1_f6_rd_e0_66` | store 2065 at `f6` | 0066 at `e0` | "
                 "**1** | **0** |"),
                ("| `w67_g6_rd_f6` | 0 | **1** | 66 | 80 | 0 | 1 · 80 |",
                 "| `w67_g6_rd_f6` | 0 | **1** | 66 | 84 | 0 | 1 · 80 |"),
                ("| `w67_f6_rd_e1_66` | store 0067 at `f6` | 0066 at `e1` | "
                 "**1** | **1** |",
                 "| `w67_f6_rd_e1_66` | store 0067 at `f6` | 0067 at `e1` | "
                 "**1** | **1** |")]
        ok = 0
        for old, new in subs:
            if old not in doc:
                print("SUBSTITUTION NOT APPLICABLE: " + old[:40])
                continue
            _, b = check(doc.replace(old, new), rows)
            if b:
                ok += 1
        print("substitutions caught: %d/%d" % (ok, len(subs)))
        return 0 if ok == len(subs) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
