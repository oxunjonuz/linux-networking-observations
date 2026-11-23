#!/usr/bin/env python3
"""f567_summary.py -- build every table of F45 from the log, not by hand.

The verifier checks the log against a model.  This script does the other
direction: it prints the numbers the document will quote, derived from the
arm lines themselves (counters, NFLOG payload diffs, sockets).  The doc is
then audited against THIS output (audit_f45_doc.py), so a table cannot drift
from the log without a red cell.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify567 import Log, hx, be16, frame_l3, ipv6_find_hdr   # noqa: E402

LOGS = os.environ.get(
    "F45_LOGS",
    "/work/kernel-sec/logs/f45_rep1.log,/work/kernel-sec/logs/f45_rep2.log"
).split(",")

L = Log(LOGS[0])
F = L.frames

ENV = {"v6": "v6", "hb": "hb", "do": "do", "hbdo": "hbdo", "fr0": "fr0",
       "frn": "frn", "none": "none", "mexth": "mexth", "mdobad": "mdobad",
       "mtrunc": "mtrunc", "t6": "t6", "p4": "p4", "mver": "mver"}


def arms(sec, door=None, env=None):
    out = []
    for a in L.arms:
        if a["sec"] != sec:
            continue
        if door and a["door"] != door:
            continue
        if env and a["env"] != env:
            continue
        out.append(a)
    return out


def get(sec, door, env, arm):
    for a in L.arms:
        if (a["sec"], a["door"], a["env"], a["arm"]) == (sec, door, env, arm):
            return a
    return None


def diff_pos(base, post, ln):
    """Where the post bytes differ from the control frame, as a list of
    (offset, length) runs, offsets relative to the IPv6 header."""
    if not post:
        return []
    out = []
    i = 0
    while i < min(len(base), len(post)):
        if base[i] != post[i]:
            j = i
            while j < min(len(base), len(post)) and base[j] != post[j]:
                j += 1
            out.append((i, j - i))
            i = j
        else:
            i += 1
    return out


CELLS = ["t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4", "t12_4", "t16_2"]
CELLS = ["t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4", "t12_4", "t16_2"]
TH_OFF = {"t0_2": 0, "t2_2": 2, "t4_2": 4, "t6_2": 6, "t8_2": 8,
          "t0_4": 0, "t12_4": 12, "t16_2": 16}
NCELLS = ["n0_1", "n0_1x", "n0_2v", "n0_2x", "n1_1", "n2_2", "n2_4", "n4_2",
          "n6_2", "n7_1", "n7_2", "n8_1", "n8_2", "n8_16", "n24_4", "n24_16",
          "n28_4", "n40_2", "n44_2"]
DOORS = ["ip6p", "inp", "ndg", "ieg"]


def live(sec, door, env, cells):
    n = 0
    for c in cells:
        a = get(sec, door, env, c)
        if a and int(a["lives"]) > 0:
            n += 1
    return n


def main():
    print("## T1  @th: live cells out of 8, per door and envelope")
    print("| door | " + " | ".join(ENV[e] for e in
                                   ("v6", "hb", "do", "hbdo")) + " |")
    print("|---" * 5 + "|")
    for d in DOORS:
        row = [str(live("td", d, e, CELLS)) for e in
               ("v6", "hb", "do", "hbdo")]
        print("| `%s` | %s |" % (d, " | ".join(row)))

    print()
    print("## T2  where the write landed (NFLOG payload diff, L3 offsets)")
    for e in ("v6", "hb", "do", "hbdo"):
        base = hx(get("td", "inp", e, "ctl")["post"])
        for c in ("t0_2", "t2_2", "t16_2"):
            a = get("td", "inp", e, c)
            post = hx(a["post"])
            d = diff_pos(base, post, 2)
            print("| `%s` | `%s` | %s | %s |" % (
                e, c, a["lives"], ",".join("%d+%d" % x for x in d) or "-"))

    print()
    print("## T3  fragments and the none-header")
    print("| door | fr0 | frn | none |")
    print("|---|---|---|---|")
    for d in DOORS:
        print("| `%s` | %s | %s | %s |" % (
            d, live("tf", d, "fr0", CELLS), live("tf", d, "frn", CELLS),
            live("tf", d, "none", CELLS)))

    print()
    print("## T4  @nh: live cells out of 19")
    print("| door | live |")
    print("|---|---|")
    for d in DOORS:
        print("| `%s` | %s |" % (d, live("nh", d, "v6", NCELLS)))
    print()
    print("| cell | ip6p | inp | ndg | ieg |")
    print("|---|---|---|---|---|")
    for c in NCELLS:
        row = []
        for d in DOORS:
            a = get("nh", d, "v6", c)
            row.append("+" if int(a["lives"]) else ".")
        print("| `%s` | %s |" % (c, " | ".join(row)))

    print()
    print("## T5  one chain, two families (door inp)")
    print("| cell | IPv6 | IPv4 |")
    print("|---|---|---|")
    for c in ("x2_2", "x4_2", "x7_1", "x0_2x", "x0_2v", "x0_2d",
              "xt0_2", "xt2_2", "xt12_4"):
        a6 = get("xf", "inp", "v6", c)
        a4 = get("xf", "inp", "p4", c)
        # the IPv4 frame reaches the layer-3 hook twice (bridge copy on r0),
        # the IPv6 frame once -- the column is the verdict, not the count
        print("| `%s` | %s | %s |" % (
            c, "+" if int(a6["lives"]) else ".",
            "+" if int(a4["lives"]) else "."))
    print()
    for c in ("xt0_2", "xt2_2", "xt12_4"):
        for e in ("v6", "p4"):
            base = hx(get("xf", "inp", e, "ctl")["post"])
            post = hx(get("xf", "inp", e, c)["post"])
            print("| `%s` | `%s` | %s |" % (
                e, c, ",".join("%d+%d" % x for x in diff_pos(base, post, 2))))

    print()
    print("## T6  reads (door, envelope) -> hits out of 3")
    for d in ("inp", "ieg"):
        for e in ("v6", "hb"):
            n = sum(1 for c in ("r0_2", "r2_2", "r4_2")
                    if int(get("rd", d, e, c)["lives"]))
            print("| `%s` | `%s` | %d/3 |" % (d, e, n))

    print()
    print("## T7  meta verdicts on inp")
    print("| section | env | l4_17 | l4_59 | pr_86 |")
    print("|---|---|---|---|---|")
    for sec in ("mp", "mp_l3"):
        for e in ("v6", "none", "mexth", "mdobad"):
            a = [get(sec, "inp", e, c) for c in ("l4_17", "l4_59", "pr_86")]
            if None in a:
                continue
            print("| `%s` | `%s` | %s | %s | %s |" % (
                sec, e, a[0]["lives"], a[1]["lives"], a[2]["lives"]))

    print()
    print("## T8  malformed matrix: (chain counter, writes, Ip6 counter)")
    print("| section | door | frame | cntp | th0_2 | th2_2 | i6 = "
          "in/hdr/trun/deliv |")
    print("|---|---|---|---|---|---|---|")
    for sec, door in (("md_both_ndg", "ndg"), ("md_both_ieg", "ieg"),
                      ("md_ndg_only", "ndg"), ("md_inp_l3", "inp"),
                      ("md_ip6p_l3", "ip6p"), ("md_ieg_only", "ieg"),
                      ("md_again_ieg", "ieg"), ("md_again_ndg", "ndg")):
        for e in ("mtrunc", "mexth", "mdobad", "none"):
            c = get(sec, door, e, "ctl")
            t0 = get(sec, door, e, "th0_2")
            t2 = get(sec, door, e, "th2_2")
            print("| `%s` | `%s` | `%s` | %s | %s | %s | %s/%s/%s/%s |" % (
                sec, door, e, c["cntp"], t0["lives"], t2["lives"],
                c["i6in"], c["i6hdr"], c["i6trun"], c["i6deliv"]))

    print()
    print("## T9  diagnostic: which door sees which frame")
    print("| frame | ip4p | ip6p | inp | ndg | ieg | i6in | i6deliv | u6a |")
    print("|---|---|---|---|---|---|---|---|---|")
    for d in L.diag:
        print("| `%s` | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            d["env"], d["ipp"], d["ip6p"], d["inp"], d["ndg"], d["ieg"],
            d["i6in"], d["i6deliv"], d["u6a"]))

    print()
    print("## T10  cross-family sequence")
    for x in L.xc:
        print("| %s | `%s` | %s | %s | %s | %s | %s | u4=%s u6=%s |" % (
            x["i"], x["env"], x["ipp"], x["ip6p"], x["inp"], x["ndg"],
            x["ieg"], x["u4"], x["u6"]))

    print()
    print("## T11  delivery oracle for the plain frames")
    for d in L.diag:
        print("| `%s` | u6a=%s u6b=%s |" % (d["env"], d["u6a"], d["u6b"]))

    print()
    print("## T12  @nh: the guard's verdict and the stack's, side by side")
    print("| cell | door | lives | the stack saw |")
    print("|---|---|---|---|")
    for c in NCELLS:
        for d in DOORS:
            a = get("nh", d, "v6", c)
            if not int(a["lives"]):
                continue
            fate = []
            if int(a["i6hdr"]):
                fate.append("InHdrErrors")
            if int(a["i6trun"]):
                fate.append("InTruncated")
            if int(a["i6unk"]):
                fate.append("InUnknownProtos")
            if int(a["i6deliv"]):
                fate.append("InDelivers")
            if not fate:
                fate.append("nothing")
            print("| `%s` | `%s` | %s | %s |" % (c, d, a["lives"],
                                                 ",".join(fate)))

    print()
    n_arms = len(L.arms)
    print("## counts: arms=%d frames=%d sections=%s" % (
        n_arms, len(F), sorted(set(a["sec"] for a in L.arms))))


if __name__ == "__main__":
    main()
