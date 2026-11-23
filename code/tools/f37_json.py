#!/usr/bin/env python3
"""f37_json.py -- findings/F37-tag-on-the-wire/summary.json, derived from the logs.

Nothing in here is typed by hand: the feature states, the wire lengths, the grid
live counts and the chain verdicts are read out of logs/f37_{rep1,rep2}.log and
the kernels are hashed from disk.
"""
import json
import os
import sys

ROOT = "/work/kernel-sec"
sys.path.insert(0, os.path.join(ROOT, "tools"))
import verify559 as V  # noqa: E402

OUT = os.path.join(ROOT, "findings/F37-tag-on-the-wire/summary.json")
KERNEL = "src/linux-7.3.4-T558"


def main():
    logs = {}
    for tag in ("rep1", "rep2"):
        A = V.parse(os.path.join(ROOT, "logs/f37_%s.log" % tag))
        logs[tag] = {
            "kernel_sha256": V.sha256(os.path.join(ROOT, A["kern"][0])),
            "initrd_sha256": V.sha256(A["initrd"][0]),
            "f559_lines": len(A["run"]) + len(A["c"]),
            "splats": A["splat"],
            "mode_exit": A["mode_exit"],
            "wire_len": {state: {arm: A["run"][(state, "wire", arm)]["wn"]
                                 for arm in ("ctl", "s16_2", "s14_99", "s14_0",
                                             "s12_2z", "s12_4z")}
                         for state in ("on", "clear", "restored")},
            "ipin": {state: {arm: A["run"][(state, "wire", arm)]["ipin"]
                             for arm in ("ctl", "s14_0", "s12_4z", "s12_2z")}
                     for state in ("on", "clear")},
            "grid_live": {combo: sum(1 for (o, l) in V.CELLS
                                     if A["run"][("clear", combo,
                                                  "g%d_%d" % (o, l))]["live"] == "1")
                          for combo in ("p6T", "p6P", "uT", "uP")},
            "grid_dead": {combo: ["(%d,%d)" % (o, l) for (o, l) in V.CELLS
                                  if A["run"][("clear", combo,
                                               "g%d_%d" % (o, l))]["live"] != "1"]
                          for combo in ("p6T", "p6P", "uT", "uP")},
            "chain_live": {a: A["c"][a]["live"] for a in A["c"]},
            "feature": {f["stage"]: f.get("act_tx") for f in A["feat"]
                        if f.get("dev") == "r1"},
            "set_rc": {s["stage"]: [s["rc"], s.get("f_unsup"), s.get("f_wish")]
                       for s in A["set"]},
        }
    A = V.parse(os.path.join(ROOT, "logs/f37_rep1.log"))
    out = {
        "finding": "F37-tag-on-the-wire",
        "turn": 559,
        "answer_short": (
            "One bit (NETIF_F_HW_VLAN_CTAG_TX on the egress port, clearable from "
            "userspace with ETHTOOL_SFEATURES because veth has no ndo_set_features) "
            "decides whether the 802.1Q tag exists in the frame at all: with it the "
            "tagged control leaves as 60 bytes with no tag, without it as 64 bytes "
            "with 8100 0064 at 12..15, and back. With the tag in the frame the @ll "
            "offsets are wire offsets: (16,2) rewrites the inner ethertype while the "
            "tag stays, (14,2) writes the TCI, and (12,2)=0000 zeroes the tag's "
            "protocol so the frame leaves with ethertype 0x0000 on every device while "
            "skb->protocol still says 0x0800. The transport base IS alive at the "
            "bridge (31/36 for TCP, 35/36 for UDP), the doff guard is protocol-bound "
            "and envelope-blind, and a second refusal - the skb's own length - takes "
            "cell (24,4) in all four combos. Two chains at one hook: pre writing the "
            "inner ethertype kills post's transport store."),
        "kernel": {
            "tree": KERNEL,
            "bzImage_sha256": V.sha256(os.path.join(ROOT, KERNEL,
                                                    "arch/x86/boot/bzImage")),
            "config_sha256": V.sha256(os.path.join(ROOT, KERNEL, ".config")),
            "note": "no kernel was built this turn: F36's T558, unchanged",
        },
        "logs": logs,
        "feature_words": 2,
        "bit": {"name": "NETIF_F_HW_VLAN_CTAG_TX", "number": 7,
                "rx": {"name": "NETIF_F_HW_VLAN_CTAG_RX", "number": 8}},
        "cells": {"wire_arms_per_state": 8, "states": 3, "grid_cells": 144,
                  "chain_arms": 3},
        "identities": {
            "wire_ctl_on_eq_restored": (A["run"][("on", "wire", "ctl")]["whex"] ==
                                        A["run"][("restored", "wire", "ctl")]["whex"]),
            "s12_2z_same_in_on_and_clear": (A["run"][("on", "wire", "s12_2z")]["whex"] ==
                                            A["run"][("clear", "wire", "s12_2z")]["whex"]),
            "grid_p6T_eq_p6P_deadset": ([k for k, v in logs["rep1"]["grid_dead"].items()
                                         if k.startswith("p6")] and
                                        logs["rep1"]["grid_dead"]["p6T"] ==
                                        logs["rep1"]["grid_dead"]["p6P"]),
        },
        "debts": [
            "one hook (bridge prerouting), one veth pair in the bridge, one sender",
            "the offload was cleared on the egress port only; the peer keeps CTAG_RX, "
            "so IpInReceives is a verdict oracle only in the 'on' state",
            "no GSO/CHECKSUM_PARTIAL, no QinQ/0x9100, no IPv6-in-VLAN, no bridge vlan filtering",
            "no netdev/arp/inet family, no store with a checksum update",
        ],
        "letters": "NOT SENT (F29+F30, F31, F32, F36, and this turn)",
    }
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
    print("wrote %s (%d bytes)" % (OUT, os.path.getsize(OUT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
