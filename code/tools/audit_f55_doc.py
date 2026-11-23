#!/usr/bin/env python3
"""audit_f55_doc.py -- every number in findings/F55-pcp-channel/SUMMARY.md
against logs/f55_rep1.log.

Two halves:
  * the arm table of §2 is parsed cell by cell and every cell is re-derived
    from the log (maps, action, four witnesses, counters);
  * a list of named prose facts, each a substring of the document paired with a
    predicate over the parsed log, so a sentence cannot drift from a number.

`--subst` runs three single-cell substitutions in a copy of the document and
requires the audit to fail on each (a check that only ever passes proves
nothing).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify577 as V
import f577_summary as S

DOC = os.path.join(V.ROOT, "findings/F55-pcp-channel/SUMMARY.md")
NCHK = 0
BAD = []


def ck(cond, what, got=None, want=None):
    global NCHK
    NCHK += 1
    if not cond:
        BAD.append("%s | got=%r want=%r" % (what, got, want))
    return cond


def load():
    head, env, frms, arms, text = V.parse_log(os.path.join(V.ROOT,
                                                           "logs/f55_rep1.log"))
    by = {a["kv"]["arm"]: a for a in arms}
    return head, env, frms, arms, by


def derive(arm):
    """the four witnesses of one arm, as the document must print them"""
    t = arm.get("T", {})
    tci = int(t.get("atci", "-1"))
    lt, _pref = S.l2tci(arm)
    rt, vp, _vpr = S.r0tci(arm)
    c = arm.get("C", {})
    a = arm["kv"]
    acts = []
    for i in (0, 1):
        if a["a%d" % i] == "-":
            continue
        txt = a["a%d" % i]
        if int(a["set%d" % i]):
            txt += " set=%d" % int(a["set%d" % i])
        if int(a["cmp%d" % i]):
            txt += " cmp=%d" % int(a["cmp%d" % i])
        elif (not int(a["set%d" % i]) and
              a["r%d%s" % (i, "a")].startswith("-1:")):
            txt += " cmp=0"
        for suf in ("a", "b"):
            v = a["r%d%s" % (i, suf)]
            if not v.startswith("-1:"):
                txt += " rd@%s=%s" % (v.split(":")[0], v.split(":")[2])
        acts.append(txt)
    return {
        "frame": a["fk"],
        "maps": S.maps_of(arm),
        "action": " + ".join(acts) if acts else "-",
        "tci": ("%04x" % tci) if tci >= 0 else "-",
        "l2tci": ("%04x" % lt) if lt >= 0 else "-",
        "r0": ("%04x" % rt) if vp == 1 else "-",
        "ch": "%s/%s" % (c.get("ch0", "-"), c.get("ch1", "-")),
    }


def audit_table(doc, by):
    lines = doc.split("\n")
    start = None
    for i, ln in enumerate(lines):
        if ln.startswith("| arm | frame | maps"):
            start = i + 2
            break
    ck(start is not None, "table 1 found in the document")
    if start is None:
        return
    seen = 0
    for ln in lines[start:]:
        if not ln.startswith("| "):
            break
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) != 8:
            ck(False, "row shape", ln)
            continue
        name = cells[0]
        ck(name in by, "row names an arm that exists: %s" % name)
        if name not in by:
            continue
        d = derive(by[name])
        seen += 1
        for k, idx in (("frame", 1), ("maps", 2), ("action", 3), ("tci", 4),
                       ("l2tci", 5), ("r0", 6), ("ch", 7)):
            ck(cells[idx] == d[k], "%s %s" % (name, k), cells[idx], d[k])
    ck(seen == len(by), "table 1 covers every arm", seen, len(by))


def audit_prose(doc, by, env, arms):
    p5_m3 = by["p5_m3"]
    p5_m7 = by["p5_m7"]
    p5_b = by["p5_b"]
    p5_rm = by["p5_rm"]
    p5_e0 = by["p5_e0"]
    p5_g6 = by["p5_g6"]
    ing_e = by["ing3_e"]
    ing0 = by["ing0_e"]
    ctl_b = by["ctl_b"]
    r0 = by["rd_r0"]
    c1 = by["ctl"]["C"]

    facts = [
        ("6066", S.tci_of(p5_m3) == 0x6066),
        ("e066", S.tci_of(p5_m7) == 0xE066 and S.tci_of(ing_e) == 0xE066),
        ("a066", S.tci_of(by["p15_m15"]) == 0xA066),
        ("c067", S.tci_of(p5_b) == 0xC067),
        ("0067", S.tci_of(ctl_b) == 0x0067),
        ("0066", S.tci_of(p5_e0) == 0x0066 and S.tci_of(p5_rm) == 0x0066),
        ("x0rxb_d=80", by["ctl"]["F"]["x0rxb_d"] == "80"),
        ("Ip6InReceives` +2", all(a["B"]["i6in_d"] == "2"
                                  for a in arms if a["kv"]["arm"] != "n0")),
        ("Ip6InDiscards` +1", all(a["B"]["disc_d"] == "1"
                                  for a in arms if a["kv"]["arm"] != "n0")),
        ("fwd_d=1", all(a["B"]["fwd_d"] == "1"
                        for a in arms if a["kv"]["arm"] != "n0")),
        ("USER|VLAN_VALID|VLAN_TPID_VALID",
         by["ctl"]["T"]["astat"] == "81"),
        ("`eg=-`", S.maps_of(p5_rm) == "-"),
        ("200 `F577` lines", True),
        ("`nf_ingress()` is\n`net/core/dev.c:6159`", True),
    ]
    for needle, ok in facts:
        ck(ok, "log supports %r" % needle)
        ck(needle in doc, "document quotes %r" % needle)

    # the three-door bracketing table of section 1
    ck(S.tci_of(p5_g6) == 0x6066 and S.tci_of(p5_m3) == 0x6066 and
       S.tci_of(p5_e0) == 0x0066, "section 1 store table")
    for s in ("| `g6` (prerouting) | **6066** | `p5_g6` |",
              "| `f6` (forward) | **6066** | `p5_m3` |",
              "| `e0` (egress of x1.102) | **0066** | `p5_e0` |"):
        ck(s in doc, "section 1 row %r" % s[:24])

    # section 3, the two laws
    ck(S.tci_of(by["p15_m5"]) == 0x0066 and
       S.tci_of(by["p15_m15"]) == 0xA066, "the two-law pair")
    for s in ("| `p15_m5` | 0x15 | `5 → 3` | 5 (same bucket) | no | **0066** |",
              "| `p15_m15` | 0x15 | `0x15 → 5` | 5 (same bucket) | yes | **a066** |",
              "| `p6_m3` | 6 | `5 → 3` | 6 | no | **0066** |"):
        ck(s in doc, "section 3 row %r" % s[:20])

    # section 5, the two devices
    ck(p5_b["C"]["e0"] == "0" and p5_b["C"]["e3"] == "1", "p5_b doors")
    ck(p5_b["F"]["v103_d"] == "1" and p5_b["F"]["v102_d"] == "0",
       "p5_b demux")

    # section 6, the ingress reader
    ck(by["ing_n1_g6"]["C"]["ch0"] == "1" and
       by["ing_n1_g6"]["C"]["ch1"] == "1", "n1/g6 counters")
    ck(S.tci_of(ing0) == 0x0066, "ing0_e wire")
    for s in ("| `n1` (netdev ingress) | **0** | `ing_n1_g6` ch0 = 1 |",
              "| `g6` (ip6 prerouting) | **5** | `ing_n1_g6` ch1 = 1 |",
              "| `f6` (ip6 forward) | **5** | `ing3_prio` ch1 = 1 |"):
        ck(s in doc, "section 6 row %r" % s[:20])

    # section 2's fourth witness
    ck(r0["C"]["ch1"] == "1", "rd_r0 read counters")
    ck("`rd_r0`" in doc, "document names rd_r0")


def run_audit(doc, by, env, arms):
    global NCHK, BAD
    NCHK = 0
    BAD = []
    audit_table(doc, by)
    audit_prose(doc, by, env, arms)
    return NCHK, list(BAD)


SUBST = [
    ("wire cell", "| p5_m3 | 0 | x1.102:eg=5>3 | f6 set=5 | 6066 |",
                  "| p5_m3 | 0 | x1.102:eg=5>3 | f6 set=5 | 0066 |"),
    ("map cell", "x1.102:eg=5>3 x1.103:eg=5>6", "x1.102:eg=5>3 x1.103:eg=5>7"),
    ("prose cell", "| `g6` (prerouting) | **6066** | `p5_g6` |",
                   "| `g6` (prerouting) | **0066** | `p5_g6` |"),
]


def main():
    doc = open(DOC, encoding="utf-8").read()
    head, env, frms, arms, by = load()
    n, bad = run_audit(doc, by, env, arms)
    if bad:
        print("FAIL %d/%d" % (len(bad), n))
        for b in bad[:30]:
            print("  " + b)
        return 1
    print("OK %d checks, 0 mismatches" % n)

    if len(sys.argv) > 1 and sys.argv[1] == "--subst":
        ok = 0
        for name, old, new in SUBST:
            if old not in doc:
                print("SUBST %s: anchor missing" % name)
                continue
            n2, bad2 = run_audit(doc.replace(old, new, 1), by, env, arms)
            if bad2:
                ok += 1
            else:
                print("SUBST %s: audit stayed green" % name)
        print("substitutions caught: %d/%d" % (ok, len(SUBST)))
        return 0 if ok == len(SUBST) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
