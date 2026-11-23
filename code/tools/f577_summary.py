#!/usr/bin/env python3
"""f577_summary.py -- the tables of the F55 document, derived from the logs.

Nothing here is typed by hand: every cell comes from logs/f55_rep1.log (and the
two boots are checked to agree by verify577.py).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify577 as V

LOGDIR = os.environ.get("F577_LOGDIR", os.path.join(V.ROOT, "logs"))


def tci_of(arm):
    t = arm.get("T", {})
    return int(t.get("atci", "-1"))


def l2tci(arm):
    """the TCI inside the egress door's L2 header"""
    for mm in V.msgs(arm.get("M", {})):
        if mm.get("prefix") in ("p2", "p3") and mm["llen"] == 18:
            return int(mm["l"][28:32], 16), mm["prefix"]
    return -1, "-"


def r0tci(arm):
    for mm in V.msgs(arm.get("M", {})):
        if mm.get("prefix") == "p5":
            return mm["vtci"], mm["vpresent"], mm["vproto"]
    return -1, -1, -1


def maps_of(arm):
    m = V.maps_from_q(arm["q"])
    out = []
    for dev in ("x1.101", "x1.102", "x1.103"):
        for kind, key in (("in", "in"), ("eg", "eg")):
            d = m[dev][kind]
            if d:
                out.append("%s:%s=%s" % (dev, kind,
                                         ",".join("%d>%d" % (k, d[k])
                                                  for k in sorted(d))))
    return " ".join(out) if out else "-"


def main():
    head, env, frms, arms, text = V.parse_log(os.path.join(LOGDIR,
                                                           "f55_rep1.log"))
    print("## Table 1 -- every arm: maps, the action, the wire\n")
    print("| arm | frame | maps (kernel readback) | action | auxdata tci | "
          "e0/e3 L2 tci | r0 VLAN attr | ch0/ch1 |")
    print("|---|---|---|---|---|---|---|---|")
    for arm in arms:
        a = arm["kv"]
        c = arm.get("C", {})
        lt, pref = l2tci(arm)
        rt, vp, vpr = r0tci(arm)
        acts = []
        for i in (0, 1):
            if a["a%d" % i] == "-":
                continue
            txt = a["a%d" % i]
            if int(a["set%d" % i]):
                txt += " set=%d" % int(a["set%d" % i])
            if int(a["cmp%d" % i]):
                txt += " cmp=%d" % int(a["cmp%d" % i])
            # an action with no store, no read and no nonzero comparator is a
            # comparator against 0: the A line cannot tell 0 from "none",
            # but the rule with nothing to compare against would be a bare
            # accept, and the design has no such arm.
            elif (not int(a["set%d" % i]) and
                  a["r%d%s" % (i, "a")].startswith("-1:")):
                txt += " cmp=0"
            for suf in ("a", "b"):
                v = a["r%d%s" % (i, suf)]
                if not v.startswith("-1:"):
                    txt += " rd@%s=%s" % (v.split(":")[0], v.split(":")[2])
            acts.append(txt)
        t = tci_of(arm)
        print("| %s | %s | %s | %s | %s | %s | %s | %s/%s |" % (
            a["arm"], a["fk"], maps_of(arm),
            " + ".join(acts) if acts else "-",
            ("%04x" % t) if t >= 0 else "-",
            ("%04x" % lt) if lt >= 0 else "-",
            ("%04x" % rt) if vp == 1 else "-",
            c.get("ch0", "-"), c.get("ch1", "-")))
    print()
    print("## Table 2 -- what each witness says, by arm\n")
    print("| arm | f6 | g6 | e0 | e3 | n1 | r0 | i6in | disc | fwd | "
          "v102 | v103 | tap len | auxn |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for arm in arms:
        c = arm.get("C", {})
        b = arm.get("B", {})
        f = arm.get("F", {})
        t = arm.get("T", {})
        print("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | "
              "%s | %s | %s |" % (
                  arm["kv"]["arm"], c.get("f6", "-"), c.get("g6", "-"),
                  c.get("e0", "-"), c.get("e3", "-"), c.get("n1", "-"),
                  c.get("r0", "-"), b.get("i6in_d", "-"), b.get("disc_d", "-"),
                  b.get("fwd_d", "-"), f.get("v102_d", "-"),
                  f.get("v103_d", "-"),
                  t.get("t0", "").split(":")[2] if t.get("t0") else "-",
                  t.get("auxn", "-")))
    print()
    print("## Table 3 -- the egress scene per arm\n")
    print("| arm | outdev | HWHEADER len | L2 len | L2 head | payload len |")
    print("|---|---|---|---|---|---|")
    for arm in arms:
        for mm in V.msgs(arm.get("M", {})):
            if mm.get("prefix") in ("p2", "p3"):
                print("| %s | %d | %d | %d | %s | %d |" % (
                    arm["kv"]["arm"], mm["outdev"], mm["hlen"], mm["llen"],
                    mm["l"][:36], mm["plen"]))
    print()
    print("## Table 4 -- the far end and the ingress device\n")
    print("| arm | p4 vtci | p4 hlen | p4 h | p5 vtci | p5 vpresent | "
          "p5 h | p5 plen |")
    print("|---|---|---|---|---|---|---|---|")
    for arm in arms:
        d = {}
        for mm in V.msgs(arm.get("M", {})):
            if mm.get("prefix") in ("p4", "p5"):
                d[mm["prefix"]] = mm
        if not d:
            continue
        p4 = d.get("p4", {})
        p5 = d.get("p5", {})
        print("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            arm["kv"]["arm"],
            ("%04x" % p4["vtci"]) if p4 else "-", p4.get("hlen", "-"),
            p4.get("h", "-"), ("%04x" % p5["vtci"]) if p5 else "-",
            p5.get("vpresent", "-"), p5.get("h", "-"), p5.get("plen", "-")))
    print()
    print("## Table 5 -- counters and sysctls of the run\n")
    print("| item | value |")
    print("|---|---|")
    print("| settle | %s |" % (env.get("settle", {}).get("st")))
    print("| frames | f0 %d bytes, f3 %d, fb %d |" %
          (int(env["l0"]), int(env["l3"]), int(env["lb"])))
    print("| tap | auxdata tpid %s, status bits %s |" %
          (arms[1]["T"].get("atpid"), arms[1]["T"].get("astat")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
