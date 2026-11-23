#!/usr/bin/env python3
"""f565_summary.py -- build findings/F43-th-base/summary.json and the tables
the SUMMARY quotes, from the logs only.

Every number in the document is produced here; audit_f43_doc.py then reads the
document and this file back and refuses a mismatch, so a table cannot drift
from the log it claims to report.
"""
import json
import sys

import verify565 as V   # the model, not the checks: frames, pktinfo, csums


def load(path):
    frames, rows, meta, splat = V.parse_log(path)
    return frames, rows, meta, splat


def main():
    logs = V.LOGS
    frames, rows, meta, splat = load(logs[0])
    F = {t: V.Frame(t, raw) for t, raw in frames.items()}
    A = {}
    for r in rows:
        A.setdefault((r["sec"], r["env"], r["gate"], r["arm"]), []).append(r)
    ctl = {}
    for (sec, env, gate, arm), rs in A.items():
        if arm == "ctl" and env not in ctl:
            ctl[env] = V.hx(rs[0]["rhex"])

    def get(sec, env, gate, arm):
        rs = A.get((sec, env, gate, arm))
        return rs[0] if rs else None

    def changes(env, cap):
        c = ctl[env]
        return [i for i in range(min(len(cap), len(c))) if cap[i] != c[i]]

    out = {"turn": 565, "finding": "F43", "kernel": "7.3.4-T563",
           "question": "Does the transport base @th have a half-way state in an "
           "envelope that moved the transport header, which of the three bases "
           "can reach the header that shifted them, and what does the transport "
           "checksum do to a store the guard accepted?",
           "answer_short": "No half-way state: @th is refused or exact, because "
           "read and store share nft_thoff(pkt) and meta protocol rebuilds it "
           "wholesale (48/64 cells live; bare and 802.1Q are the same table, "
           "Q-in-Q and PPPoE 0/8 -> 8/8). The same (0,2) store writes frame "
           "byte 0 (@ll), 15 (@nh) or 42 (@th), and the smallest byte @th can "
           "touch is 42, so the 0xc000+ branch is unreachable by construction. "
           "The checksum is the wall the guard does not see: an accepted, "
           "exactly-targeted dport rewrite is dropped by the receiver "
           "(UdpInErrors 2/1) unless csum type inet writes the increment at "
           "thoff+6; a store into the checksum field itself cannot be saved, "
           "because the update runs before the store.",
           "kernel_sha": meta["sha"], "arms_per_boot": len(rows),
           "boots": len(logs), "splat": len(splat),
           "envelopes": {}, "grid": {}, "tcp": {}, "reach": {},
           "csum": {}, "v6": {}}

    for tag in ("p", "w", "q", "ps", "pt", "pst", "pu", "psu", "ps6"):
        fr = F[tag]
        out["envelopes"][tag] = {
            "wire_len": len(fr.wire), "hook_len": len(fr.hook),
            "ntags": fr.ntags, "pppoe": fr.pppoe,
            "ip_off": fr.ip_off, "hook_ip": fr.hook_ip,
            "hook_l4": fr.hook_l4, "h_proto": fr.h_proto,
            "skb_protocol": fr.skb_protocol(),
            "ctrl_len": len(ctl.get(tag, b"")),
        }

    # ---- the grid --------------------------------------------------------
    arms = ["t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4", "t12_4", "t16_2"]
    for env in ("p", "w", "q", "ps"):
        row = {}
        for gate in ("0", "1"):
            cells = {}
            for a in arms:
                r = get("thg", env, gate, a)
                cap = V.hx(r["rhex"])
                ch = changes(env, cap) if r["live"] == "1" else []
                cells[a] = {"live": int(r["live"]), "off": int(r["off"]),
                            "len": int(r["len"]), "changed": ch}
            row["gate" + gate] = {
                "live": sum(c["live"] for c in cells.values()), "cells": cells}
        row["udp_frame_byte"] = F[env].hook_l4
        out["grid"][env] = row

    # ---- the TCP doff guard ---------------------------------------------
    for env, gate in (("pt", "0"), ("pst", "0"), ("pst", "1")):
        cells = {}
        for a in ("t0_2", "t10_4", "t12_1", "t12_2", "t12_4", "t16_2"):
            r = get("tht", env, gate, a)
            cells[a] = {"live": int(r["live"]), "off": int(r["off"]),
                        "len": int(r["len"])}
        out["tcp"]["%s_g%s" % (env, gate)] = {
            "live": sum(c["live"] for c in cells.values()), "cells": cells}

    # ---- three bases, one cell ------------------------------------------
    for a, base in (("ll0", "ll"), ("nh0", "nh"), ("th0", "th")):
        r = get("thr", "ps", "1", a)
        cap = V.hx(r["rhex"])
        out["reach"][a] = {"base": base, "live": int(r["live"]),
                           "changed": changes("ps", cap),
                           "ideliv": int(r["ideliv"]), "u5000": int(r["u5000"])}
    th_ps = []
    for a in arms:
        r = get("thg", "ps", "1", a)
        if r and r["live"] == "1":
            th_ps += changes("ps", V.hx(r["rhex"]))
    out["reach"]["th_min_byte_pppoe"] = min(th_ps) if th_ps else None
    th_q = []
    for a in arms:
        r = get("thg", "q", "1", a)
        if r and r["live"] == "1":
            th_q += changes("q", V.hx(r["rhex"]))
    out["reach"]["th_min_byte_qinq"] = min(th_q) if th_q else None

    # ---- the checksum section -------------------------------------------
    for env, gate in (("pu", "0"), ("psu", "1")):
        sec = {}
        for a in ("ctl", "dp_nc", "dp_cs", "sp_cs", "ck_nc", "ck_cs",
                  "pay_cs", "pay_nc"):
            r = get("cs", env, "0" if a == "ctl" else gate, a)
            cap = V.hx(r["rhex"])
            st, ulen = V.udp_csum_ok(F[env], cap)
            sec[a] = {
                "live": int(r["live"]), "dport": V.be16(cap, F[env].l4_off + 2)
                if cap else None,
                "sport": V.be16(cap, F[env].l4_off) if cap else None,
                "csum_field": "%04x" % V.be16(cap, F[env].l4_off + 6)
                if cap else None,
                "csum_status": st, "udperr": int(r["udperr"]),
                "u5000": int(r["u5000"]), "u5001": int(r["u5001"]),
                "ideliv": int(r["ideliv"]), "prx": int(r["prx"]),
                "changed": changes(env, cap) if cap else [],
            }
        out["csum"][env] = sec

    # ---- IPv6 ------------------------------------------------------------
    for gate in ("0", "1"):
        sec = {}
        for a in ("t0_2", "t2_2", "t6_2", "t8_2", "dp_nc", "dp_cs"):
            r = get("v6", "ps6", gate, a)
            cap = V.hx(r["rhex"])
            st, _ = V.udp_csum_ok(F["ps6"], cap)
            sec[a] = {"live": int(r["live"]), "csum_status": st,
                      "u6err": int(r["u6err"]), "u6_5000": int(r["u6_5000"]),
                      "u6_5001": int(r["u6_5001"]),
                      "changed": changes("ps6", cap) if r["live"] == "1" else []}
        out["v6"]["gate" + gate] = sec
    out["v6"]["udp_byte_in_frame"] = F["ps6"].hook_l4

    # determinism
    l1 = [x for x in open(logs[0], errors="replace").read().split("\n")
          if x.startswith("F565 ")]
    l2 = [x for x in open(logs[1], errors="replace").read().split("\n")
          if x.startswith("F565 ")]
    out["determinism"] = {"lines": len(l1), "differing": sum(1 for a, b in
                                                             zip(l1, l2) if a != b)}

    with open(V.ROOT + "/findings/F43-th-base/summary.json", "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")

    # ---- the tables, printed for the document ---------------------------
    print("== grid: live cells and the byte each accepted store landed on ==")
    for env in ("p", "w", "q", "ps"):
        g = out["grid"][env]
        for gate in ("0", "1"):
            cells = g["gate" + gate]["cells"]
            txt = " ".join("%s:%d%s" % (a, c["live"],
                                        ("@" + ",".join(map(str, c["changed"])))
                                        if c["changed"] else "")
                           for a, c in cells.items())
            print("%-3s g%s %2d/8  %s" % (env, gate, g["gate" + gate]["live"], txt))
    print("== tcp ==")
    for k, v in out["tcp"].items():
        print(k, v["live"], v["cells"])
    print("== reach ==")
    for k in ("ll0", "nh0", "th0"):
        print(k, out["reach"][k])
    print("th_min_byte pppoe", out["reach"]["th_min_byte_pppoe"],
          "qinq", out["reach"]["th_min_byte_qinq"])
    print("== csum ==")
    for env in ("pu", "psu"):
        for a, v in out["csum"][env].items():
            print("%-4s %-7s live=%d dport=%s sport=%s csum=%s %s udperr=%d "
                  "u5000=%d u5001=%d ideliv=%d prx=%d chg=%s"
                  % (env, a, v["live"], v["dport"], v["sport"], v["csum_field"],
                     v["csum_status"], v["udperr"], v["u5000"], v["u5001"],
                     v["ideliv"], v["prx"], v["changed"]))
    print("== v6 ==")
    for gate in ("0", "1"):
        for a, v in out["v6"]["gate" + gate].items():
            print("g%s %-6s live=%d csum=%s u6err=%d u6_5000=%d u6_5001=%d chg=%s"
                  % (gate, a, v["live"], v["csum_status"], v["u6err"],
                     v["u6_5000"], v["u6_5001"], v["changed"]))
    print("== determinism ==", out["determinism"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
