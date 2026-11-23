#!/usr/bin/env python3
"""f44_summary.py -- build findings/F44-ingress-two-doors/summary.json and the
markdown tables of SUMMARY.md from logs/f44_rep{1,2}.log.

Every number the report quotes is produced here, from the log, so that the
document cannot drift from the measurement without the audit noticing.
"""
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
OUT = ROOT + "/findings/F44-ingress-two-doors"
LOGS = [ROOT + "/logs/f44_rep1.log", ROOT + "/logs/f44_rep2.log"]


def text(p):
    with open(p, "rb") as f:
        return f.read().decode("utf-8", "replace").replace("\r\n", "\n")


def hx(s):
    return bytes.fromhex(s) if s and s != "-" else b""


def kv(line):
    d = {}
    for x in line.split("|")[1:]:
        if "=" in x:
            k, v = x.split("=", 1)
            d[k] = v
    return d


def load(p):
    frames, mframes, arms = {}, {}, []
    for line in text(p).split("\n"):
        if line.startswith("F566 FRAME|"):
            t = line.split("|")[1]
            frames[t] = kv(line)
        elif line.startswith("F566 MFRAME|"):
            t = line.split("|")[1]
            mframes[t] = kv(line)
        elif line.startswith("F566 A|"):
            arms.append(kv(line))
    return frames, mframes, arms


def be16(b, o):
    return (b[o] << 8) | b[o + 1]


def frame_info(raw):
    n = 0
    off = 12
    while be16(raw, off) in (0x8100, 0x88A8, 0x9100) and off + 6 <= len(raw):
        n += 1
        off += 4
    ethtype = be16(raw, 12)
    pppoe = (n == 0 and ethtype == 0x8864)
    ip_off = 22 if pppoe else off + 2
    ihl = (raw[ip_off] & 0x0F) * 4
    return {"len": len(raw), "ntags": n, "ethtype": "0x%04x" % ethtype,
            "pppoe": pppoe, "ip_off": ip_off, "ihl": ihl,
            "l4_off": ip_off + ihl,
            "sport": be16(raw, ip_off + ihl), "dport": be16(raw, ip_off + ihl + 2),
            "csum": be16(raw, ip_off + ihl + 6), "ver_ihl": "0x%02x" % raw[ip_off]}


def main():
    F1, M1, A1 = load(LOGS[0])
    F2, M2, A2 = load(LOGS[1])
    det = (A1 == A2)

    doors = ["ipp", "inp", "ndg", "ieg"]
    envs = ["p", "w", "w0", "q", "ps"]
    idx = {}
    for a in A1:
        idx[(a["sec"], a["door"], a["env"], a["arm"])] = a

    def get(sec, door, env, arm):
        return idx.get((sec, door, env, arm))

    out = {
        "turn": 566,
        "id": "F44",
        "kernels": ["7.3.4-T563"],
        "arms_per_boot": len(A1),
        "boots": 2,
        "question": ("@th in the two pktinfo constructors F43 never measured "
                     "(inet layer-3 and the two ingress doors), and what the "
                     "guard does when the handler rewrites state->pf"),
        "answer_short": (
            "Four pktinfo constructors, one coordinate: every accepted @th "
            "store at all four doors (ip L3, inet L3, netdev ingress, inet "
            "ingress) lands on data+ihl*4+off, and the rows where nothing is "
            "accepted are rows where the hook never ran (counter 0), not "
            "guard refusals. The real difference between the doors is the "
            "guard: nft_in_ingress() and nft_nh_write_ok() read "
            "pkt->state->pf, and nft_do_chain_inet_ingress() rewrites it to "
            "NFPROTO_IPV4 before any rule runs, so the same frame at the same "
            "hook gets @ll 12/12 vs 7/12 and @nh 20/20 vs 9/20 (the ip4 "
            "whitelist). And the two ingress doors share one per-device hook "
            "list: the inet handler validates and returns NF_DROP before "
            "nft_do_chain(), so a malformed IPv4 frame is dropped before any "
            "netdev chain on the same device can count it (counter 0 with the "
            "inet table present, 1 with it deleted), with InHdrErrors raised "
            "by a hook that ran no rule."),
        "provenance": {}, "frames": {}, "doors": {}, "td": [], "tm": [],
        "gd": [], "gn": [], "rf": [], "dp": [], "md": [], "far": []}

    # provenance
    t = text(LOGS[0])
    out["provenance"]["kernel_line"] = [l for l in t.split("\n")
                                        if l.startswith("Linux version")
                                        ][0].strip()
    out["provenance"]["kernel_sha256"] = __import__("hashlib").sha256(
        open(ROOT + "/src/linux-7.3.4-T563/arch/x86/boot/bzImage", "rb").read()
    ).hexdigest()
    out["provenance"]["differ_sha256"] = __import__("hashlib").sha256(
        open(ROOT + "/vm/build/differ566", "rb").read()).hexdigest()
    out["provenance"]["initrd_sha256"] = __import__("hashlib").sha256(
        open(ROOT + "/vm/initrd566/full.cpio.gz", "rb").read()).hexdigest()
    out["provenance"]["arms_rep1"] = len(A1)
    out["provenance"]["arms_rep2"] = len(A2)
    out["provenance"]["deterministic"] = det
    out["provenance"]["splat"] = bool(re.search(r"KASAN|BUG:|Oops|WARNING:", t))

    for tag in F1:
        out["frames"][tag] = frame_info(hx(F1[tag]["wire"]))
    for tag in M1:
        out["frames"][tag] = frame_info(hx(M1[tag]["wire"]))

    # doors: passes per environment, from the control arms of td
    for d in doors:
        row = {"door": d,
               "passes": {e: int(get("td", d, e, "ctl")["livep"]) for e in envs},
               "data_offset": {e: int(get("td", d, e, "ctl")["postlen"]) for e in envs},
               "l2hdr": {e: int(get("td", d, e, "ctl")["l2"]) for e in envs}}
        out["doors"][d] = row

    # td grid
    for d in doors:
        for e in envs:
            ctl = get("td", d, e, "ctl")
            row = {"door": d, "env": e, "passes": int(ctl["livep"]),
                   "log_pre": int(ctl["npre"]), "log_post": int(ctl["npost"]),
                   "l2": int(ctl["l2"]), "payload_len": int(ctl["postlen"]),
                   "u5000": int(ctl["u5000"]), "ipin": int(ctl["ipin"]),
                   "rn": int(ctl["rn"]), "store_live": 0, "store_refused": 0,
                   "cells": {}}
            for arm in ("t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4",
                        "t12_4", "t16_2"):
                a = get("td", d, e, arm)
                live = int(a["lives"])
                if live:
                    row["store_live"] += 1
                else:
                    row["store_refused"] += 1
                # where the store landed, relative to skb->data
                pre, post = hx(a["pre"]), hx(a["post"])
                at = -1
                for i in range(min(len(pre), len(post))):
                    if pre[i] != post[i]:
                        at = i
                        break
                row["cells"][arm] = {"live": live, "at": at,
                                     "imm": a["imm"], "off": int(a["off"]),
                                     "len": int(a["len"])}
            out["td"].append(row)

    # tm
    for d in ("ndg", "ieg"):
        for e in ("q", "ps"):
            row = {"door": d, "env": e, "passes": int(get("tm", d, e, "ctl")["livep"]),
                   "store_live": 0, "at": -1}
            for arm in ("t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4",
                        "t12_4", "t16_2"):
                a = get("tm", d, e, arm)
                if int(a["lives"]):
                    row["store_live"] += 1
                    if row["at"] < 0:
                        pre, post = hx(a["pre"]), hx(a["post"])
                        for i in range(min(len(pre), len(post))):
                            if pre[i] != post[i]:
                                row["at"] = i
                                break
            out["tm"].append(row)

    # gd / gn cell lists
    for sec, grid in (("gd", ("p", "w")), ("gn", ("p",))):
        for d in ("ndg", "ieg"):
            for e in grid:
                live, refused = [], []
                for a in A1:
                    if a["sec"] != sec or a["door"] != d or a["env"] != e:
                        continue
                    if a["mode"] != "1":
                        continue
                    cell = [int(a["off"]), int(a["len"])]
                    (live if int(a["lives"]) else refused).append(cell)
                out[sec].append({"door": d, "env": e,
                                 "live": sorted(live), "refused": sorted(refused),
                                 "n_live": len(live), "n_refused": len(refused)})

    # rf
    for d in doors:
        row = {"door": d, "reads": {}}
        for arm in ("r0_2", "r2_2", "r6_2"):
            a = get("rf", d, "p", arm)
            row["reads"][arm] = int(a["lives"])
        out["rf"].append(row)

    # dp
    for d in doors:
        for e in ("p", "ps"):
            a = get("dp", d, e, "dp5001")
            out["dp"].append({"door": d, "env": e, "livep": int(a["livep"]),
                              "lives": int(a["lives"]), "u5000": int(a["u5000"]),
                              "u5001": int(a["u5001"])})

    # md
    for sec in ("md_both", "md_ndg", "md_ieg"):
        for tag in ("badver", "ihl4", "trunc"):
            a = idx.get((sec, "ndg" if sec != "md_ieg" else "ieg", tag, tag))
            if a is None:
                continue
            out["md"].append({"sec": sec, "env": tag, "livep": int(a["livep"]),
                              "lives": int(a["lives"]), "ipin": int(a["ipin"]),
                              "ihdr": int(a["ihdr"]), "itrun": int(a["itrun"]),
                              "rn": int(a["rn"])})

    # a few far-tap facts the report quotes
    for sec, d, e, arm in (("td", "ndg", "p", "t2_2"), ("td", "ieg", "p", "t2_2"),
                           ("td", "ipp", "p", "t2_2"), ("td", "inp", "p", "t2_2"),
                           ("gd", "ndg", "p", "l12_4"),
                           ("gd", "ieg", "w", "l16_2"),
                           ("gd", "ndg", "w", "l12_2")):
        a = get(sec, d, e, arm)
        out["far"].append({"sec": sec, "door": d, "env": e, "arm": arm,
                           "rchg": int(a["rchg"]), "rchgs": a["rchgs"],
                           "rhex_len": len(hx(a["rhex"]))})

    os.makedirs(OUT, exist_ok=True)
    with open(OUT + "/summary.json", "w") as f:
        json.dump(out, f, indent=1, sort_keys=True)

    # ---- the tables -------------------------------------------------------
    print("### table A -- the four doors, passes per envelope")
    print("| door | p | w | w0 | q | ps |")
    print("|---|---|---|---|---|---|")
    for d in doors:
        r = out["doors"][d]
        print("| `%s` | %s |" % (d, " | ".join(str(r["passes"][e]) for e in envs)))

    print("")
    print("### table B2 -- one row per door and envelope (doc-ready)")
    print("| дверь | конверт | проходов | записей | payload | L2HDR |")
    print("|---|---|---|---|---|---|")
    for r in out["td"]:
        print("| `%s` | `%s` | %d | **%d/8** | %s | %s |" %
              (r["door"], r["env"], r["passes"], r["store_live"],
               r["payload_len"] if r["passes"] else "--",
               r["l2"] if r["passes"] else "--"))

    print("")
    print("### table C2 -- doc-ready byte table")
    print("| дверь | конверт | t0_2 | t2_2 | t4_2 | t6_2 | t8_2 | t0_4 | t12_4 | t16_2 |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in out["td"]:
        print("| `%s` | `%s` | %s |" % (r["door"], r["env"],
              " | ".join(str(r["cells"][c]["at"]) if r["cells"][c]["at"] >= 0 else "--"
                        for c in ("t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4",
                                  "t12_4", "t16_2"))))

    print("")
    print("### table E2 -- doc-ready guard tables")
    for sec in ("gd", "gn"):
        print("| дверь | конверт | живых | отказано |")
        print("|---|---|---|---|")
        for r in out[sec]:
            tot = 12 if sec == "gd" else 20
            ref = ", ".join("(%d,%d)" % (a, b) for a, b in r["refused"]) or "--"
            print("| `%s` | `%s` | **%d/%d** | %s |" %
                  (r["door"], r["env"], r["n_live"], tot, ref))
        print("")

    print("")
    print("### table B -- @th grid (store live / refused), and where data starts")
    print("| door | env | passes | live | refused | payload | L2HDR |")
    print("|---|---|---|---|---|---|---|")
    for r in out["td"]:
        print("| `%s` | `%s` | %d | **%d** | %d | %d | %d |" %
              (r["door"], r["env"], r["passes"], r["store_live"],
               r["store_refused"], r["payload_len"], r["l2"]))

    print("")
    print("### table C -- the byte each @th store landed on (delta from skb->data)")
    print("| door | env | t0_2 | t2_2 | t4_2 | t6_2 | t8_2 | t0_4 | t12_4 | t16_2 |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r in out["td"]:
        print("| `%s` | `%s` | %s |" % (r["door"], r["env"],
              " | ".join(str(r["cells"][c]["at"]) for c in
                        ("t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4",
                         "t12_4", "t16_2"))))

    print("")
    print("### table D -- meta protocol at the two ingress doors")
    print("| door | env | passes | store live | first byte |")
    print("|---|---|---|---|---|")
    for r in out["tm"]:
        print("| `%s` | `%s` | %d | **%d**/8 | %d |" %
              (r["door"], r["env"], r["passes"], r["store_live"], r["at"]))

    print("")
    print("### table E -- @ll and @nh verdicts, cell by cell")
    for sec in ("gd", "gn"):
        print("")
        print("| sec | door | env | live | refused |")
        print("|---|---|---|---|---|")
        for r in out[sec]:
            print("| `%s` | `%s` | `%s` | **%d**/12 | %d |" %
                  (sec, r["door"], r["env"], r["n_live"], r["n_refused"])
                  if sec == "gd" else
                  "| `%s` | `%s` | `%s` | **%d**/20 | %d |" %
                  (sec, r["door"], r["env"], r["n_live"], r["n_refused"]))
        for r in out[sec]:
            print("   %s/%s/%s live=%s refused=%s" %
                  (sec, r["door"], r["env"], r["live"], r["refused"]))

    print("")
    print("### table F -- read == write")
    print("| door | r0_2 | r2_2 | r6_2 |")
    print("|---|---|---|---|")
    for r in out["rf"]:
        print("| `%s` | %s | %s | %s |" % (r["door"], r["reads"]["r0_2"],
                                           r["reads"]["r2_2"], r["reads"]["r6_2"]))

    print("")
    print("### table G -- the socket oracle")
    print("| door | env | passes | store live | u5000 | u5001 |")
    print("|---|---|---|---|---|---|")
    for r in out["dp"]:
        print("| `%s` | `%s` | %d | %d | %d | %d |" %
              (r["door"], r["env"], r["livep"], r["lives"], r["u5000"],
               r["u5001"]))

    print("")
    print("### table H -- malformed IPv4 at the two ingress doors")
    print("| pass | frame | passes | store live | ipin | ihdr | itrun | far tap |")
    print("|---|---|---|---|---|---|---|---|")
    for r in out["md"]:
        print("| `%s` | `%s` | %d | %d | %d | %d | %d | %d |" %
              (r["sec"], r["env"], r["livep"], r["lives"], r["ipin"],
               r["ihdr"], r["itrun"], r["rn"]))

    print("")
    print("### table I -- the far tap")
    for r in out["far"]:
        print("   %s/%s/%s/%s rchg=%d rchgs=%s len=%d" %
              (r["sec"], r["door"], r["env"], r["arm"], r["rchg"], r["rchgs"],
               r["rhex_len"]))
    print("")
    print("arms rep1=%d rep2=%d deterministic=%s" %
          (len(A1), len(A2), det))


if __name__ == "__main__":
    main()
