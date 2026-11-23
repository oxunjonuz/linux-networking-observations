#!/usr/bin/env python3
"""f39_summary.py -- build findings/F39-8021ad-qinq/summary.json from the logs.

Numbers are derived here, never typed: the document and the JSON both come out
of logs/f39_*.log, and audit_f39_doc.py re-derives the document's cells.
"""
import importlib.util
import json
import os

ROOT = "/work/kernel-sec"
spec = importlib.util.spec_from_file_location("v", os.path.join(
    ROOT, "tools/verify561.py"))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

rows = v.parse(os.path.join(ROOT, "logs/f39_rep1.log"))
farA = v.parse(os.path.join(ROOT, "logs/f39_farA.log"))
farB = v.parse(os.path.join(ROOT, "logs/f39_farB.log"))
out = {
    "finding": "F39",
    "turn": 561,
    "title": "802.1AD (0x88a8) and Q-in-Q: one pop, two TPIDs, two feature bits",
    "kernel": {
        "version": "7.3.4-T558",
        "sha256": v.sha256(os.path.join(
            ROOT, "src/linux-7.3.4-T558/arch/x86/boot/bzImage")),
        "new_kernel_built": False,
    },
    "boots": {
        "battery": ["logs/f39_rep1.log", "logs/f39_rep2.log"],
        "far_dedicated": ["logs/f39_farA.log", "logs/f39_farB.log"],
        "f561_lines_per_battery_boot": len(
            [1 for l in open(os.path.join(ROOT, "logs/f39_rep1.log"),
                             errors="replace") if l.startswith("F561 ")]),
    },
    "representations": {k: [t[0] for t in v.REPS[k]] for k in v.ORDER},
    "meta_protocol": {},
    "ll_grid": {},
    "nh_bridge": {},
    "nh_unlock": {},
    "xmit": {},
    "far": {},
    "ndin": {},
}
for rep in v.ORDER:
    mt = [x for x in v.getr(rows, "M", rep=rep) if x["want"] != "-"]
    out["meta_protocol"][rep] = [x["want"] for x in mt if int(x["live"]) > 0]
    sub = v.getr(rows, "R", env="ll." + rep)
    live = sorted((int(x["off"]), int(x["len"])) for x in sub
                  if int(x["live"]) > 0 and x["arm"] != "ctl")
    out["ll_grid"][rep] = {"live": len(live), "cells": live}
for rep, env in (("w", "w.bare"), ("q", "q.bare")):
    sub = v.getr(rows, "R", env="unlock." + env)
    out["nh_bridge"][rep] = len([x for x in sub
                                 if int(x["live"]) > 0 and x["arm"] != "ctl"])
for env in ("w.bare", "w.meta", "q.bare", "q.meta"):
    sub = v.getr(rows, "R", env="unlock." + env)
    out["nh_unlock"][env] = len([x for x in sub
                                 if int(x["live"]) > 0 and x["arm"] != "ctl"])
for state in ("A_11", "B_01", "C_00"):
    d = {}
    for arm in ("ctl", "p8100", "p88a8", "p0000", "t88a8"):
        x = v.one(rows, "R", env="xmit.%s.%s" % (state, arm), arm=arm)
        d[arm] = {"wire_len": int(x["wn"]), "wire_tag": x["whex"][24:32],
                  "far_len": int(x["rn"])}
    out["xmit"][state] = d
for tag, rs in (("farA", farA), ("farB", farB)):
    out["far"][tag] = {x["rep"]: {"wire_len": int(x["wn"]),
                                  "far_len": int(x["rn"]),
                                  "ipin": int(x["ipin"])}
                       for x in v.getr(rs, "FAR")}
for rep in ("p", "q"):
    x = v.one(rows, "R", env="ndin." + rep, arm="g8_1")
    sub = [y for y in v.getr(rows, "R", env="ndin." + rep)
           if int(y["live"]) > 0 and y["arm"] != "ctl"]
    out["ndin"][rep] = {"live": len(sub), "g8_1_bytes": x["wchgs"]}
out["feature_bits"] = {"NETIF_F_HW_VLAN_CTAG_TX": 7,
                       "NETIF_F_HW_VLAN_STAG_TX": 45,
                       "note": "aliases in the enum do not consume a value"}
p = os.path.join(ROOT, "findings/F39-8021ad-qinq/summary.json")
open(p, "w").write(json.dumps(out, indent=1, sort_keys=True) + "\n")
print(p, os.path.getsize(p))
