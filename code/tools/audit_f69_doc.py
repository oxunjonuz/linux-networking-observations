#!/usr/bin/env python3
"""audit_f69_doc.py -- does SUMMARY.md say what the logs measured?

Two halves:
  (a) every number the document quotes from the run is looked up in
      findings/F69-segment-price/summary.json (which f591_summary.py built from
      the logs) and must be there, in the form the document writes it;
  (b) three single substitutions are made in a COPY of the document and the
      same audit must then FAIL on each -- a document checker that cannot go
      red is decoration.

Usage: audit_f69_doc.py [doc]
"""
import json
import re
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F69-segment-price/SUMMARY.md"
SUM = ROOT + "/findings/F69-segment-price/summary.json"

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


def audit(doc, S):
    global PASS, FAIL
    PASS = FAIL = 0
    FAILS.clear()

    # ---- provenance numbers
    ck(S["predictions_sha"].startswith("96069ce4"), "doc/pred-sha-recorded",
       S["predictions_sha"][:8])
    ck("96069ce4" in doc, "doc/pred-sha-quoted")
    ck("4a34d3e4" in doc, "doc/differ-sha-quoted")
    ck(S["differ_sha"].startswith("4a34d3e4"), "doc/differ-sha-recorded",
       S["differ_sha"][:8])
    ck("1efbc957" in doc, "doc/kernel-sha-quoted")

    # ---- the cap table: in the LINE that names the arm, so that a number
    #      quoted correctly elsewhere cannot mask a wrong one
    lines = doc.splitlines()
    run0 = S["runs"][0]
    for a in run0["arms"]:
        if a["kind"] != "c":
            continue
        arm_lines = [l for l in lines if "`%s`" % a["name"] in l]
        ck(bool(arm_lines), "doc/cap-arm-present", a["name"])
        for uh in {u for att in a["attempts"] for u in att["uh"]}:
            ck(any("%04x" % uh in l and str(uh) in l for l in arm_lines),
               "doc/cap-uh-in-arm-line/%s" % a["name"],
               "%04x/%d" % (uh, uh))

    # ---- the price ladder
    ladder = {}
    for a in run0["arms"]:
        if a["kind"] == "q":
            ladder[(a["pl"], a["n"], a["door"])] = a["attempts"][0]["rmem"]
    s512 = ladder[(512, 1, "f")]
    s1200 = ladder[(1200, 1, "f")]
    ck(s512 == 1280, "doc/s512", s512)
    ck(s1200 == 2304, "doc/s1200", s1200)
    for (P, k, door), rmem in sorted(ladder.items()):
        want = (2 * k - 1) * s512 if door == "f" else k * s512
        if P == 1200:
            want = (2 * k - 1) * s1200 if door == "f" else k * s1200
        ck(rmem == want, "doc/ladder-model/%d/%d/%s" % (P, k, door),
           "%d != %d" % (rmem, want))
        # the ladder table row for this k must carry the number twice
        # (bold and plain) -- once is a stray mention, twice is the row
        row = [l for l in lines if l.startswith("| %d |" % k)]
        if door == "f":
            ck(bool(row) and str(rmem) in row[0] and row[0].count(str(rmem)) >= 2,
               "doc/ladder-row/%d/%d" % (P, k),
               "%r" % (row[0] if row else None))
        else:
            ck(str(rmem) in doc, "doc/ladder-linear-quoted/%d/%d" % (P, k),
               rmem)
            # the linear cells are quoted in prose next to the arm's name
            name = next(a["name"] for a in run0["arms"]
                        if a["kind"] == "q" and a["n"] == k and a["pl"] == P
                        and a["door"] == door)
            found = any("`%s`" % name in l and str(rmem) in l for l in lines)
            ck(found, "doc/ladder-linear-row/%d/%d" % (P, k),
               "%s %d" % (name, rmem))
        # and the multiplier the document prints next to it
        ck("(2k−1)·%d" % s512 in doc or "(2k−1)·%d" % s1200 in doc,
           "doc/ladder-formula")

    # ---- the arithmetical claims about the old wobble
    ck("127 × 1280" in doc, "doc/127-units")
    ck("1280 / 64 = 20" in doc, "doc/twenty-bytes")
    ck(ladder[(512, 64, "f")] == 127 * 1280, "doc/162560-is-127-units",
       ladder[(512, 64, "f")])
    # the anomaly is one unit less, and that is what the document says
    ck(162560 - 161280 == s512, "doc/anomaly-is-one-unit",
       162560 - 161280)
    ck("162560 − 161280 = **1280**" in doc, "doc/anomaly-sentence")

    # ---- the byte boundary pair
    ck("x1636t_f" in doc and "x993t_u" in doc, "doc/boundary-arms")
    ck("65535" in doc and "65536" in doc, "doc/boundary-bytes")
    ck(str(2 * 28 + 65479) == "65535", "doc/2h-plus-65479")
    ck(str(2 * 28 + 65480) == "65536", "doc/2h-plus-65480")

    # ---- counts of the turn
    ck("6047" in doc, "doc/check-count")
    ck("25/25" in doc, "doc/selftest-count")
    ck("26 из 26" in doc, "doc/prediction-count")
    ck("двенадцать" in doc, "doc/twelve-measurements")
    ck(str(len(S["runs"][0]["arms"])) == "33", "doc/arm-total",
       len(S["runs"][0]["arms"]))
    ck("33 плеч" in doc, "doc/arm-total-quoted")
    ck("14" in doc and "19" in doc, "doc/mode-sizes")
    ck(sum(1 for a in run0["arms"] if a["kind"] == "c") == 14,
       "doc/cap-arms-14")
    ck(sum(1 for a in run0["arms"] if a["kind"] == "q") == 19,
       "doc/price-arms-19")

    # ---- the erratum must name the cell it corrects
    ck("0xfc08" in doc, "doc/erratum-cell")
    ck("F68 §9" in doc or "F68" in doc, "doc/erratum-source")
    return PASS, FAIL, list(FAILS)


def main():
    doc = open(sys.argv[1] if len(sys.argv) > 1 else DOC,
               encoding="utf-8").read()
    S = json.load(open(SUM))
    p, f, fails = audit(doc, S)
    print("audit: %d checks passed, %d failed" % (p, f))
    for x in fails[:20]:
        print("FAIL:", x)
    if f:
        return 1
    # ---- can the audit go red?  three single substitutions
    muts = [
        ("txth-exact-byte", "`ffcf` (65487)", "`ffcf` (65488)"),
        ("cell-uh", "**`f96b` (63851) + `066d` (1645)**",
         "**`f96b` (63850) + `066d` (1645)**"),
        ("anomaly-unit", "162560 − 161280 = **1280**",
         "162560 − 161280 = **1281**"),
        ("ladder-cell", "| 16 | **39680** | 39680 |", "| 16 | **39681** | 39680 |"),
        ("count", "**6047 проверок, 0**", "**6048 проверок, 0**"),
    ]
    ok = 0
    for name, old, new in muts:
        if doc.count(old) != 1:
            print("SAMPLE_NOT_FOUND", name, doc.count(old))
            continue
        p2, f2, _ = audit(doc.replace(old, new), S)
        if f2 > 0:
            print("mutation %-16s caught by %d check(s)" % (name, f2))
            ok += 1
        else:
            print("mutation %-16s SURVIVED -- the audit is decoration" % name)
    print("mutations caught: %d/%d" % (ok, len(muts)))
    return 0 if ok == len(muts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
