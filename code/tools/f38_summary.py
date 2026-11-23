#!/usr/bin/env python3
"""f38_summary.py -- turn 560 / F38.

Every number that goes into findings/F38-recv-side-of-the-tag/SUMMARY.md is
derived HERE, from the two counted logs, and never typed by hand.  The script
prints markdown tables and writes summary.json; tools/verify560.py re-derives
the same numbers by a different path and tools/audit_f38_doc.py checks that the
document's cells still match the JSON.

usage: f38_summary.py [--json OUT]
"""
import json
import sys
from collections import OrderedDict

LOG1 = "/work/kernel-sec/logs/f38_rep1.log"
LOG2 = "/work/kernel-sec/logs/f38_rep2.log"
OUT = "/work/kernel-sec/findings/F38-recv-side-of-the-tag/summary.json"


def rows(path):
    out = []
    with open(path, "rb") as f:
        for raw in f:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line.startswith("F560 R|"):
                continue
            d = {}
            for kv in line.split("|")[1:]:
                k, _, v = kv.partition("=")
                d[k] = v
            for k in ("off", "len", "store", "rc", "live", "wn", "rn"):
                d[k] = int(d[k])
            out.append(d)
    return out


def meta(path):
    out = {}
    with open(path, "rb") as f:
        for raw in f:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            for pre in ("F560 REP|", "F560 SECTION|", "F560 TAGSTORE|",
                        "F560 KERNEL|", "F560 NFL|"):
                if line.startswith(pre):
                    d = {"_kind": pre.strip("|").split()[1]}
                    for kv in line.split("|")[1:]:
                        k, _, v = kv.partition("=")
                        d[k] = v
                    out.setdefault(d["_kind"], []).append(d)
    return out


def cellset(rs):
    return {r["arm"] for r in rs if r["arm"] != "ctl"}


def ctl(rs):
    for r in rs:
        if r["arm"] == "ctl":
            return r
    return None


def main():
    r1, r2 = rows(LOG1), rows(LOG2)
    m1 = meta(LOG1)
    same = [(a["env"], a["arm"], a["live"], a["whex"], a["rhex"])
            for a in r1] == [(a["env"], a["arm"], a["live"], a["whex"],
                              a["rhex"]) for a in r2]
    envs = OrderedDict()
    for r in r1:
        envs.setdefault(r["env"], []).append(r)

    j = {"turn": 560, "finding": "F38", "rep_identical": same,
         "arms": len(r1), "envs": {}}

    print("## rep1 == rep2: %s  (arms=%d)\n" % ("yes" if same else "NO",
                                                len(r1)))
    print("| env | control live | wn | rn | cells | live | dead |")
    print("|---|---|---|---|---|---|---|")
    for env, rs in envs.items():
        c = ctl(rs)
        cells = [r for r in rs if r["arm"] != "ctl"]
        live = [r for r in cells if r["live"] > 0]
        j["envs"][env] = {
            "ctl_live": c["live"] if c else None,
            "ctl_wn": c["wn"] if c else None,
            "ctl_rn": c["rn"] if c else None,
            "ctrl_whex": c["whex"] if c else None,
            "ctrl_rhex": c["rhex"] if c else None,
            "cells": len(cells),
            "live": len(live),
            "live_set": sorted(r["arm"] for r in live),
            "dead_set": sorted(r["arm"] for r in cells if r["live"] == 0),
        }
        print("| %s | %s | %s | %s | %d | **%d** | %s |"
              % (env, c["live"] if c else "-", c["wn"] if c else "-",
                 c["rn"] if c else "-", len(cells), len(live),
                 ", ".join(sorted(r["arm"] for r in cells
                                  if r["live"] == 0))))
    print()

    # the three identities
    idents = []
    a = cellset(envs.get("recv.p", []))
    b = cellset(envs.get("recv.x91", []))     # only_x: 8 cells
    if a and b:
        sub = {x for x in a if x in
               {"g10_4", "g12_1", "g12_2", "g12_4", "g14_2", "g16_1",
                "g16_2", "g16_4"}}
        idents.append(("recv.p vs recv.x91 on the 8 tag-sensitive cells",
                       sub == b))
    for pair in (("recv.w100", "recv.v0"), ("arp.a", "arp.aw100")):
        x, y = envs.get(pair[0], []), envs.get(pair[1], [])
        if x and y:
            xs, ys = cellset(x), cellset(y)
            if pair[0].startswith("recv"):
                keep = {"g10_4", "g12_1", "g12_2", "g12_4", "g14_2",
                        "g16_1", "g16_2", "g16_4"}
                xs, ys = xs & keep, ys & keep
            idents.append(("%s vs %s (dead sets)" % pair, xs == ys))
    print("| identity | holds |")
    print("|---|---|")
    for name, ok in idents:
        print("| %s | **%s** |" % (name, "yes" if ok else "NO"))
        j.setdefault("identities", {})[name] = ok
    print()

    # byte facts
    facts = {}
    pc, wc, xc, mc = (ctl(envs.get("recv.p", [])), ctl(envs.get("recv.w100", [])),
                      ctl(envs.get("recv.x91", [])), ctl(envs.get("recv.m100", [])))
    if pc and wc:
        facts["recv_far_identical_p_w100"] = pc["rhex"] == wc["rhex"]
        facts["recv_far_bytes"] = pc["rhex"]
    if xc:
        facts["recv_x91_wire_len"] = len(xc["whex"]) // 2
        facts["recv_x91_wire_12_16"] = xc["whex"][24:32]
        facts["recv_x91_ctrl_rhex_12_16"] = xc["rhex"][24:32]
    if mc and pc:
        facts["probe_m100_ctl_wire_equals_plain"] = mc["whex"] == pc["whex"]
    tagstore = m1.get("TAGSTORE", [])
    facts["tagstore"] = tagstore
    # the same cell, three representations, at the ingress hook
    idx = {}
    for env in ("ndin.p", "ndin.w100", "ndin.x91"):
        for r in envs.get(env, []):
            if r["arm"] == "g8_1":
                diff = [s for s in r["wchgs"].split(",") if ":" in s]
                idx[env] = {"wchg": r["wchgs"], "whex": r["whex"],
                            "rhex": r["rhex"], "live": r["live"]}
    facts["ndin_g8_1"] = idx
    # ARP: the 16-byte write past the end of the message
    for env in ("arp.a", "arp.aw100"):
        for r in envs.get(env, []):
            if r["arm"] == "x20_16":
                ch = [s.split(":")[0] for s in r["wchgs"].split(",") if ":" in s]
                lo, hi = min(int(x) for x in ch), max(int(x) for x in ch)
                msg0 = 18 if env.endswith("aw100") else 14
                facts.setdefault("arp_x20_16", {})[env] = {
                    "first": lo, "last": hi, "nbytes": len(ch),
                    "msg_last": msg0 + 27, "past": sum(1 for x in ch
                                                       if int(x) > msg0 + 27),
                    "live": r["live"], "whex": r["whex"]}
    # drop: verdicts
    dr = {}
    for r in envs.get("drop.drop", []):
        dr[r["arm"]] = {"live": r["live"], "rn": r["rn"], "wn": r["wn"]}
    facts["drop"] = dr
    j["facts"] = facts

    print("| byte fact | value |")
    print("|---|---|")
    for k in sorted(facts):
        v = facts[k]
        if isinstance(v, (str, int, bool)):
            print("| %s | `%s` |" % (k, v))
    print()

    if OUT:
        with open(OUT, "w") as f:
            json.dump(j, f, indent=1, sort_keys=True)
            f.write("\n")
        print("written: %s" % OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
