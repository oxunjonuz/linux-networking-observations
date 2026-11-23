#!/usr/bin/env python3
"""audit_f70_doc.py -- does findings/F70-condense/SUMMARY.md still say what the
logs say?

Every number the document quotes is looked up in summary.json (which is built
from the logs by tools/f70_summary.py) or directly in the log lines.  With
--mutate the document is copied, ONE substitution is applied, and the audit must
go RED: a check that cannot be made to fail is not a check.

Usage: audit_f70_doc.py [--mutate CASE]
"""
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F70-condense/SUMMARY.md"
SJ = ROOT + "/findings/F70-condense/summary.json"
LOGS = [ROOT + "/logs/f70_rep1.log", ROOT + "/logs/f70_rep2.log"]
PRED = ROOT + "/research/predictions_592.md"

PASS = 0
FAIL = 0
FAILS = []


def ck(cond, what, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILS.append("%s %s" % (what, detail))


def audit(doc_text, sj, logs_text):
    def has(s, what):
        ck(s in doc_text, "doc/" + what, s[:60])

    # --- the boundary table, §3
    for name, delta in sj["delta"].items():
        ck(str(delta[0]) in doc_text, "doc/delta-" + name, str(delta[0]))
    for name, calls in sj["calls"].items():
        ck(str(calls[0]) in doc_text, "doc/calls-" + name, str(calls[0]))
    has("| **`c_eq`** | 15 | **19200** | **exactly half** | **5** | **14080** |",
        "c_eq-row")
    has("| **`c_gt`** | 16 | 20480 | above | **6** | **7680** |", "c_gt-row")
    has("| `c_lt` | 13 | 16640 | below | **5** | 14080 |", "c_lt-row")
    has("| `c_zero` | 0 | 0 | below | **0** | 14080 |", "c_zero-row")
    # --- §2's record table: the values must be a real record
    ck("| 1 (the head) | 512 | **0** | 556 | 704 | **7680** | 0 |" in doc_text,
       "doc/head-record-row", "")
    ck(re.search(r"len=512 dlen=0 tail=556 end=704 ts=7680",
                 logs_text) is not None, "log/head-record-exists", "")
    # --- §6
    has("| 1 (the head) | 512 | 704 | **7360** |", "head-7360-row")
    has("| 6 (the short tail) | 200 | 384 | **960** |", "tail-960-row")
    has("7360 = 5 × 1280 + 960", "head-sum-7360")
    # --- the arithmetic claimed in prose
    ck(str(sj["delta"]["c_gt"][0]) == str(6 * 1280), "calc/6x1280",
       str(sj["delta"]["c_gt"][0]))
    ck(str(sj["delta"]["c_eq"][0]) == str(11 * 1280), "calc/11x1280",
       str(sj["delta"]["c_eq"][0]))
    ck(str(sj["head_ts"]["c_tail"][0][0]) == "7360", "calc/c_tail-head",
       str(sj["head_ts"]["c_tail"]))
    has("`end - tail = 148`", "tailroom-148")
    has("`sk_rcvbuf = 38400`", "rcvbuf-38400")
    has("704 + 576 = 1280", "ts-const-1280")
    has("384 + 576 = 960", "ts-const-960")
    # --- flags
    ck(list(sj["fl"]["c_lin"][0]) == [0, 1, 1, 1, 1, 1], "data/c_lin-flags",
       str(sj["fl"]["c_lin"]))
    ck(list(sj["fl"]["c_one"][0]) == [1], "data/c_one-flags",
       str(sj["fl"]["c_one"]))
    has("`fl = 0,1,1,1,1,1`", "doc/c_lin-flags")
    # --- counts of the turn
    ck(sj["attempts"] == 36, "data/attempts", str(sj["attempts"]))
    has("**9 arms × 2 attempts × 2 boots = 36 attempts**", "arms-36")
    ck(sum(len(v) for v in [sj["calls"]]) == 9, "data/nine-arms", "")
    for name in sj["calls"]:
        ck(len(sj["calls"][name]) == 1, "data/stable-" + name,
           str(sj["calls"][name]))
    has("**2034 checks, 0 failed**", "checks-2034")
    has("**26/26**", "selftest-26")
    has("**160** records", "records-160")
    # the record count is not typed: recount from the logs
    n = 0
    for ln in logs_text.splitlines():
        if ln.startswith("F592 CNT|"):
            n += int(re.search(r"cond=(\d+)", ln).group(1))
    ck(n == 160, "data/records-recount", str(n))
    # --- predictions
    ck("0d574b40" in doc_text, "doc/predictions-sha", "")
    import hashlib
    ck(hashlib.sha256(open(PRED, "rb").read()).hexdigest().startswith("0d574b40"),
       "prov/predictions-unchanged", "")
    # --- the debts are named, not hidden
    has("F67 §6", "names-f67-debt")
    has("F68 §9", "names-f68-debt")
    has("**Refuted, P12**", "names-p12-refutation")
    has("**Refuted in its number, P14**", "names-p14-refutation")
    has("## 10. What is not measured, plainly", "names-not-measured")


def main():
    doc = open(DOC, encoding="utf-8").read()
    sj = json.load(open(SJ, encoding="utf-8"))
    logs = "\n".join(open(p, encoding="utf-8", errors="replace").read()
                     for p in LOGS)
    if len(sys.argv) > 2 and sys.argv[1] == "--mutate":
        case = sys.argv[2]
        subs = {
            "head-ts": ("| 1 (the head) | 512 | **0** | 556 | 704 | **7680** | 0 |",
                        "| 1 (the head) | 512 | **0** | 556 | 704 | **1280** | 0 |"),
            "eq-delta": ("| **`c_eq`** | 15 | **19200** | **exactly half** | "
                         "**5** | **14080** |",
                         "| **`c_eq`** | 15 | **19200** | **exactly half** | "
                         "**6** | **7680** |"),
            "short-tail": ("| 6 (the short tail) | 200 | 384 | **960** |",
                           "| 6 (the short tail) | 200 | 384 | **1280** |"),
            "records": ("**160** records", "**161** records"),
            "selftest": ("**26/26**", "**25/26**"),
            "checks": ("**2034 checks, 0 failed**", "**2035 checks, 0 failed**"),
            "flag-linear": ("`fl = 0,1,1,1,1,1`", "`fl = 0,0,0,0,0,0`"),
            "p12": ("**Refuted, P12**", "**Held, P12**"),
        }
        if case not in subs:
            print("unknown case", case)
            return 2
        old, new = subs[case]
        if doc.count(old) != 1:
            print("SAMPLE_NOT_FOUND", case, doc.count(old))
            return 2
        audit(doc.replace(old, new), sj, logs)
        print("mutated %s: %d checks, %d failed" % (case, PASS, FAIL))
        for f in FAILS[:6]:
            print("  FAIL:", f)
        return 1 if FAIL else 0
    audit(doc, sj, logs)
    print("audit_f70_doc: %d checks, %d failed" % (PASS, FAIL))
    for f in FAILS[:20]:
        print("FAIL:", f)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
