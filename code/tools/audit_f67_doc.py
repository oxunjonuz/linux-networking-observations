#!/usr/bin/env python3
"""audit_f67_doc.py -- do the numbers in findings/F67-*/SUMMARY.md exist?

Three sources, checked against each other in one direction only: the document
is the claim, findings/F67-queue-head/summary.json is derived from the log by
tools/f67_summary.py, and vm/differ589_add.c is the instrument.  Every number
the document prints must appear in the JSON, every arm of the JSON must be in
the document with its own numbers on its own line, and the arm table of the
source must agree with both.

Then three single substitutions in a COPY of the document must each be caught:
a wrong check count, a wrong kept count, and a wrong buffer number.
"""
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = f"{ROOT}/findings/F67-queue-head/SUMMARY.md"
JSON = f"{ROOT}/findings/F67-queue-head/summary.json"
SRC = f"{ROOT}/vm/differ589_add.c"
VR = f"{ROOT}/findings/F67-queue-head/VERIFY_REPORT.md"

ok = 0
bad = []


def chk(cond, what):
    global ok
    if cond:
        ok += 1
    else:
        bad.append(what)


def audit(doc_text, js, src_text, vr_text):
    sub_ok, sub_bad = 0, []

    def c(cond, what):
        nonlocal sub_ok
        if cond:
            sub_ok += 1
        else:
            sub_bad.append(what)

    d = js
    # --- the header: provenance strings the document quotes
    c(d["kernel_sha256"][:8] in doc_text, "doc: kernel sha prefix")
    c(d["instrument_sha256"][:8] in doc_text, "doc: instrument sha prefix")
    c(d["predictions_sha256"][:8] in doc_text, "doc: predictions sha prefix")
    c("212992" in doc_text, "doc: the default buffer is stated")
    c("832 × 256 = 212992" in doc_text,
      "doc: the derivation of the default is printed whole")
    c(str(d["default_rcvbuf"]["derived"]) == "212992", "json: default derived")
    c(all(x == 212992 for x in d["default_rcvbuf"]["printed"]),
      "json: the socket printed 212992 in every boot")
    # --- the derived constants
    dv = d["derived"]
    for k in ("s_512", "s_1200", "cost_per_received_frame"):
        c(str(dv[k]) in doc_text, f"doc: derived {k} = {dv[k]} is printed")
    c(dv["head_charge_empty_and_below_half_512"] == 64 * dv["s_512"],
      "json: 64 x s(512) is the head below half")
    c(dv["head_charge_empty_and_below_half_1200"] == 54 * dv["s_1200"],
      "json: 54 x s(1200) is the head below half")
    c(dv["filler_total"] == 64 * dv["cost_per_received_frame"],
      "json: the filler is 64 frames at its own cost")
    # --- every arm: present in the doc, with its own numbers on its own line
    names = [a["name"] for a in d["arms"]]
    c(len(names) == 17, f"json has 17 arms, found {len(names)}")
    for a in d["arms"]:
        lines = [ln for ln in doc_text.splitlines() if a["name"] in ln]
        c(bool(lines), f"doc: arm {a['name']} appears")
        if not lines:
            continue
        nums = set()
        for ln in lines:
            nums |= {int(x) for x in re.findall(r"\d+", ln)}
        kept = a["kept"]
        errs = a["errors"]
        c(any(k in nums for k in kept),
          f"doc: {a['name']} prints its kept count {kept}")
        c(any(e in nums for e in errs),
          f"doc: {a['name']} prints its error count {errs}")
        if a["rmem"]:
            c(any(r in nums for r in a["rmem"]) or
              any(str(r) in doc_text for r in a["rmem"]),
              f"doc: {a['name']} prints the queue's byte count {a['rmem']}")
        if a["name"] not in ("d54_lazy", "d54_eag"):
            c(kept[0] == kept[1],
              f"json: {a['name']} is deterministic between the boots")
    # --- the head's charge, the claim of the turn
    head = d["head_charge"]
    c(head["c_fill_test"] == [1280, 1280],
      "json: 512 above half -> the head costs one datagram")
    c(head["c_fill_test1200_262"] == [2304, 2304],
      "json: 1200 above half -> the head costs one datagram")
    c(head["c_fill_test1200_344"] == [124416, 124416],
      "json: 1200 below half -> the head costs the whole aggregate")
    c(head["c_only_test"] == [81920, 81920], "json: empty queue -> N * s")
    c(head["c_fill_s512_212"] == [1280, 1280],
      "json: 39 of 64 kept in a buffer where N * s does not fit")
    # --- the refuted predictions, asserted exactly
    c(d["frozen"]["refuted"] == ["P10", "P11", "P12", "P14"],
      "json: the refuted set is P10 P11 P12 P14")
    c("**Опровергнуты P10, P11, P12, P14**" in doc_text,
      "doc: the refuted set is named in one sentence, without a repair")
    for p in ("P10", "P11", "P12", "P14"):
        c(p in doc_text, f"doc: {p} named among the refuted")
    c("13 из 17" in doc_text, "doc: 13 of 17 is stated")
    # --- the verification numbers
    c("1717" in doc_text, "doc: the verifier's check count")
    c("1717" in d["verification"]["verify589"] and
      "failures=0" in d["verification"]["verify589"],
      "json: verifier says 1717 checks, 0 failures")
    c("27/27" in doc_text and "27/27" in d["verification"]["selftest"],
      "doc and json agree on 27/27 mutations")
    c("1717" in vr_text, "the verify report carries the same count")
    c("27/27" in vr_text, "the verify report carries the selftest count")
    # --- the instrument on disk
    c("AF589_DFLT[] = {" in src_text, "source: dflt table present")
    c("AF589_COND[] = {" in src_text, "source: cond table present")
    src_names = re.findall(r'\{\s*"([a-z0-9_]+)",\s*\'', src_text)
    c(src_names == names,
      f"source arm order == json arm order ({len(src_names)} names)")
    c("the socket's own default" in src_text,
      "source: -1 is documented as the socket's own default")
    c(sum(1 for a in d["arms"] if a["rcvbuf_request"] < 0) == 5,
      "json: five arms ask for the true default")
    return sub_ok, sub_bad


doc = open(DOC, errors="replace").read()
js = json.load(open(JSON))
src = open(SRC, errors="replace").read()
vr = open(VR, errors="replace").read()

ok, bad = audit(doc, js, src, vr)

# ---------- the document must be able to fail --------------------------
MUTS = [
    ("a wrong check count", "1717 проверок, 0", "1716 проверок, 0"),
    ("a wrong kept count", "| `c_fill_test1200_262` | 262144 | 162560 > R/2 | "
                           "**2304** | **43** |", "| `c_fill_test1200_262` | "
                           "262144 | 162560 > R/2 | **2304** | **44** |"),
    ("a wrong buffer", "`832 × 256 = 212992`", "`832 × 256 = 212993`"),
    ("a refuted prediction silently repaired", "**Опровергнуты P10, P11, P12, P14**",
     "**Опровергнуты P10, P11, P12**"),
    ("an arm dropped from a table", "| `d1200_153600` | 76800 → **153600** | "
                                    "**13** | 41 | 152064 | 1+12 |", ""),
]
caught = 0
for what, old, new in MUTS:
    assert old in doc, f"mutation anchor missing: {what}"
    _, b = audit(doc.replace(old, new), js, src, vr)
    if b:
        caught += 1
    else:
        bad.append(f"mutation not caught: {what}")

print(f"audit: {ok} checks, {len(bad)} failures; "
      f"{caught}/{len(MUTS)} document mutations caught")
for x in bad:
    print("FAIL " + x)
sys.exit(1 if bad else 0)
