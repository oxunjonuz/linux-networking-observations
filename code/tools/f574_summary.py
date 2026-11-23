#!/usr/bin/env python3
"""f574_summary.py [log] -- the tables of the F52 report, printed from the log.

Every cell is read out of the log; nothing here is typed by hand.  The document
carries these tables verbatim, so audit_f52_doc.py can regenerate them and
compare cell by cell.
"""
import sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "/work/kernel-sec/logs/f52_rep1.log"


def kv(s):
    d = {}
    for part in s.split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k] = v
    return d


def parse(path):
    A, env = [], None
    for ln in open(path, "rb").read().decode("utf8", "replace").splitlines():
        if ln.startswith("F574 ENV|"):
            env = kv(ln)
        elif ln.startswith("F574 A|"):
            A.append({"A": kv(ln)})
        elif ln.startswith("F574 C|") and A:
            A[-1]["C"] = kv(ln)
        elif ln.startswith("F574 B|") and A:
            A[-1]["B"] = kv(ln)
        elif ln.startswith("F574 M|") and A:
            A[-1]["M"] = ln
        elif ln.startswith("F574 T|") and A:
            A[-1]["T"] = ln
    return A, env


def get(a, which, field, idx=0):
    v = a.get(which, {}).get(field, "-")
    return v.split(",")[idx]


def taps(a):
    d = {}
    for part in (a.get("T") or "").split("|"):
        if "=" not in part:
            continue
        _, rest = part.split("=", 1)
        dev, n, flen, hx = rest.split(":", 3)
        d[dev] = (int(n), int(flen), hx)
    return d


def main():
    A, env = parse(LOG)
    x0 = env["x0mac"]

    print("## T1 -- the census of five doors and the fate of the local copy")
    print("| arm | frame | door | brp | brf | brl | in6 | ndy | u6n | br0 otherhost | y0 otherhost | z0 otherhost |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for a in A:
        if a["A"]["fk"] == "A":
            continue
        print("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            a["A"]["arm"], a["A"]["fk"], a["A"]["door"],
            get(a, "C", "brp"), get(a, "C", "brf"), get(a, "C", "brl"),
            get(a, "C", "in6"), get(a, "C", "ndy"),
            a["A"]["u6n"], a["B"]["broth_d"], a["B"]["y0oth_d"],
            a["B"]["z0oth_d"]))

    print()
    print("## T2 -- `@ll` at the bridge door of the tagged frame (no VLAN device)")
    print("| arm | offset | len | imm | fires | ch |")
    print("|---|---|---|---|---|---|")
    for a in A:
        if a["A"]["door"] != "brp" or a["A"]["mode"] != "3":
            continue
        print("| %s | %s | %s | %s | %s | %s |" % (
            a["A"]["arm"], a["A"]["off"], a["A"]["len"], a["A"]["imm"],
            "yes" if get(a, "C", "brp", 1) == "1" else "no",
            get(a, "C", "brp", 1)))

    print()
    print("## T3 -- the same offsets at the ip6 door, with br0.100 up")
    print("| arm | offset | len | imm | ch |")
    print("|---|---|---|---|---|")
    for a in A:
        if a["A"]["door"] != "in6" or a["A"]["mode"] != "3":
            continue
        print("| %s | %s | %s | %s | %s |" % (
            a["A"]["arm"], a["A"]["off"], a["A"]["len"], a["A"]["imm"],
            get(a, "C", "in6", 1)))

    print()
    print("## T4 -- stores into the four tagged bytes: what the wire carries")
    print("| arm | store | rcs | ch | u6n | br0 otherhost | y0 tap len | y0 tap 12..17 |")
    print("|---|---|---|---|---|---|---|---|")
    for a in A:
        if a["A"]["mode"] != "1":
            continue
        tp = taps(a)
        y0 = tp.get("y0", (0, -1, "-"))
        hx = y0[2]
        mid = hx[24:36] if len(hx) >= 36 else "-"
        print("| %s | @ll,%s,%s = %s | %s | %s | %s | %s | %s | %s |" % (
            a["A"]["arm"], a["A"]["off"], a["A"]["len"], a["A"]["imm"],
            a["A"]["rcs"], get(a, "C", a["A"]["door"], 1), a["A"]["u6n"],
            a["B"]["broth_d"], y0[1], mid))

    print()
    print("## T5 -- the far end asked about the tag it received")
    print("| arm | door2 | imm | c2 |")
    print("|---|---|---|---|")
    for a in A:
        if a["A"].get("d2", "-") == "-":
            continue
        print("| %s | %s | %s | %s |" % (
            a["A"]["arm"], a["A"]["d2"], a["A"]["imm"],
            a.get("C", {}).get("c2", "-")))

    print()
    print("## T6 -- the counters of a death that no IPv6 counter sees")
    print("| arm | in6 door | Ip6InReceives | Ip6InDiscards | Ip6InDelivers | br0 otherhost | y0 otherhost | br0 rx_packets |")
    print("|---|---|---|---|---|---|---|---|")
    for a in A:
        if a["A"]["arm"] not in ("c100", "c0", "w14_0", "w14_100", "w12_4",
                                 "vd_c"):
            continue
        print("| %s | %s | %s | %s | %s | %s | %s | %s |" % (
            a["A"]["arm"], get(a, "C", "in6"), a["B"]["i6in_d"],
            a["B"]["disc_d"], a["B"]["deliv_d"], a["B"]["broth_d"],
            a["B"]["y0oth_d"], a["B"]["brrxp_d"]))


if __name__ == "__main__":
    main()
