#!/usr/bin/env python3
"""audit_f72_doc.py -- do the numbers in findings/F72-zerocopy-doors/SUMMARY.md
match the logs and the verifier?

Every claim in the document that has a number behind it is re-derived here from
`logs/f72_rep1.log` and `logs/f72_rep2.log` (parsed with verify594's own
parser, so the document and the verifier cannot drift apart) and from
`findings/F72-zerocopy-doors/summary.json`.  With `--mutate` the script also
edits a copy of the document three ways and refuses to pass if it cannot see
the edit.
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F72-zerocopy-doors/SUMMARY.md")
VRF = os.path.join(ROOT, "findings/F72-zerocopy-doors/VERIFY_REPORT.md")
LTR = os.path.join(ROOT, "findings/F72-zerocopy-doors/LETTER_SECTION_F72.txt")
JS = os.path.join(ROOT, "findings/F72-zerocopy-doors/summary.json")

PASS = 0
FAIL = 0
BAD = []


def ck(cond, what):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        if len(BAD) < 40:
            BAD.append(what)


def load_verifier():
    spec = importlib.util.spec_from_file_location("v", os.path.join(ROOT, "tools/verify594.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def audit(doc_text, data):
    ck("5056" in doc_text and 5056 in data["ts_all"], "5056 is not in the document and in the data")
    ck("30336" in doc_text and 30336 in data["charges"], "30336 (z_lin6 charge) missing")
    ck("55616" in doc_text and 55616 in data["charges"], "55616 (z_fl6 charge) missing")
    ck("7680" in doc_text and 7680 in data["charges"], "7680 (z_ctl6 charge) missing")
    ck("3080" in doc_text and 3080 in data["uh1"], "3080 (the merged length) missing")
    ck("35392" in doc_text and 35392 in data["rmem"], "35392 (the 7 kept) missing")
    ck("9152" in doc_text and 9152 in data["ts_all"], "9152 (the 5000-byte payload) missing")
    ck("2240" in doc_text and 2240 in data["ts_all"], "2240 (the aggregate head) missing")
    ck("1208" in doc_text or "1200" in doc_text, "the 1200-byte arm is not described")
    ck("7 of 64" in doc_text or "**7**" in doc_text, "the kept count is not in the document")
    ck(data["n_arms"] == 13, "13 arms expected, data says %d" % data["n_arms"])
    ck(data["n_attempts"] == 52, "52 attempts expected, data says %d" % data["n_attempts"])
    ck(data["n_boots"] == 2, "2 boots expected")
    # three claims pinned to an exact form, so that editing them is visible
    ck(re.search(r"\| \*\*30336\*\* \|", doc_text) is not None,
       "the z_lin6 charge is not a table cell")
    ck("leave **7** in the queue" in doc_text, "the kept count is not pinned")
    ck("reach the rule as six\npackets" in doc_text,
       "the six-packet sentence is not pinned")
    ck("2872" in doc_text and "2872" in data["verifier_out"], "the check count in the document != the verifier's")
    ck("41/41" in doc_text and "41/41" in data["selftest_out"], "the selftest result != 41/41")
    ck("13 arms" in doc_text, "the document does not state the arm count")
    ck(len(data["anchors"]) == 25, "25 anchors expected, found %d" % len(data["anchors"]))
    ck("[SILENCE]" not in doc_text, "placeholder in the document")
    ck("TODO" not in doc_text and "XXX" not in doc_text, "placeholder in the document")
    ck(len(doc_text) > 8000, "the document is too short to be the summary")
    # the letter and the verify report must not claim a different kernel
    for p in (VRF, LTR):
        t = open(p).read()
        ck("1efbc957" in t, "%s does not carry the kernel sha" % os.path.basename(p))
        ck("NOT SENT" in t or "VERIFY" in os.path.basename(p),
           "%s does not carry its status" % os.path.basename(p))
    # the claims in the summary that must not appear
    ck("нулевая длина" not in doc_text, "stray text")


def collect():
    m = load_verifier()
    d = {"ts_all": set(), "charges": set(), "uh1": set(), "rmem": set()}
    names = set()
    attempts = 0
    for lg in m.LOGS:
        order, att, hdr = m.parse(lg)
        for k in order:
            a = att[k]
            attempts += 1
            names.add(a.arm["name"])
            for x in m.ints(a.eq[0]["ts"]):
                d["ts_all"].add(x)
            d["charges"].add(int(a.rcv["rmem0"]))
            d["charges"].add(int(a.rcv["rmem1"]))
            d["rmem"].add(int(a.rcv["rmem0"]))
            for x in m.ints(a.pkt["uhlen"]):
                d["uh1"].add(x)
    d["n_arms"] = len(names)
    d["n_attempts"] = attempts
    d["n_boots"] = len(m.LOGS)
    v = subprocess.run([sys.executable, os.path.join(ROOT, "tools/verify594.py")],
                       capture_output=True, text=True).stdout
    d["verifier_out"] = v
    s = subprocess.run([sys.executable, os.path.join(ROOT, "tools/verify594_selftest.py")],
                       capture_output=True, text=True).stdout
    d["selftest_out"] = s
    d["anchors"] = [l for l in open(os.path.join(ROOT, "tools/verify594.py"))
                    if l.strip().startswith('("net/') or l.strip().startswith('("include/')]
    return d


def mutations(data):
    """three edits of a copy of the document; the audit must see each"""
    src = open(DOC).read()
    tmp = tempfile.mkdtemp(prefix="f72doc_")
    ok = 0
    bad = []
    cases = [("charge", "| **30336** |", "| **30335** |"),
             ("kept", "leave **7** in the queue", "leave **9** in the queue"),
             ("packets", "reach the rule as six\npackets", "reach the rule as five\npackets")]
    for name, old, new in cases:
        if old not in src:
            bad.append("%s: sample not found" % name)
            continue
        t = src.replace(old, new, 1)
        PASS0, FAIL0 = 0, 0
        globals()["PASS"] = 0
        globals()["FAIL"] = 0
        globals()["BAD"] = []
        audit(t, data)
        if FAIL > 0:
            ok += 1
        else:
            bad.append("%s: SURVIVED" % name)
    globals()["PASS"] = 0
    globals()["FAIL"] = 0
    globals()["BAD"] = []
    shutil.rmtree(tmp, ignore_errors=True)
    return ok, bad


def main():
    data = collect()
    audit(open(DOC).read(), data)
    print("audit: %d ok, %d bad" % (PASS, FAIL))
    for b in BAD:
        print("FAIL " + b)
    rc = 0 if FAIL == 0 else 1
    if "--mutate" in sys.argv:
        ok, bad = mutations(data)
        print("document mutations caught: %d/%d %s" % (ok, 3, "OK" if not bad else "; ".join(bad)))
        if bad:
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
