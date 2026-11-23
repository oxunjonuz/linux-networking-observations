#!/usr/bin/env python3
"""f36_summary.py -- derive the turn-558 tables from the logs.

Nothing in the SUMMARY is typed: every number below is parsed out of
logs/f36_{V_rep1,V_rep2,T_rep1}.log and written to summary.json; the markdown
tables printed on stdout are what SUMMARY.md carries, and audit_f36_doc.py
re-derives them and checks them back.
"""
import hashlib
import json
import os
import sys

ROOT = "/work/kernel-sec"
LOGS = ["V_rep1", "V_rep2", "T_rep1"]
OFFS = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
LENS = [1, 2, 4]
CELLS = [(o, l) for o in OFFS for l in LENS]
BY = ["ctl", "ctl_plain", "s16_2_plain", "s16_2", "s14_99", "s14_0",
      "s14_1064", "s12_4z"]
WHAT = {
    "ctl": "tagged frame, no store",
    "ctl_plain": "plain frame, no store",
    "s16_2_plain": "(16,2) on a plain frame",
    "s16_2": "(16,2) = 0x0806",
    "s14_99": "(14,2) = 0x0099",
    "s14_0": "(14,2) = 0x0000",
    "s14_1064": "(14,2) = 0x1064",
    "s12_4z": "(12,4) = 0x8100 0x0000",
}


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def fields(line):
    return dict(kv.split("=", 1) for kv in line.rstrip("\n").split("|")[1:]
                if "=" in kv)


def parse(tag):
    p = os.path.join(ROOT, "logs", "f36_%s.log" % tag)
    out = {"run": {}, "view": {}, "r557": {}, "ctl557": {}, "grid": {},
           "vlandev": [], "why": [], "one": [], "kernel_sha": None}
    for line in open(p, errors="replace"):
        if line.startswith("F558 RUN|"):
            d = fields(line)
            out["run"][(d["env"], d["arm"])] = d
        elif line.startswith("F558 VIEW|"):
            d = fields(line)
            out["view"][(d["env"], d["arm"], d["view"])] = d
        elif line.startswith("F557 R|"):
            d = fields(line)
            out["r557"][(d["env"], d["arm"])] = d
        elif line.startswith("F557 CTL|"):
            d = fields(line)
            out["ctl557"][d["env"]] = d
        elif line.startswith("F558 GRID|"):
            d = fields(line)
            out["grid"][d["env"]] = d
        elif line.startswith("F558 VLANDEV|"):
            d = fields(line)
            d["_raw"] = line.strip()
            out["vlandev"].append(d)
        elif line.startswith("F558 WHY|"):
            d = fields(line)
            d["_t"] = line.rstrip("\n").split("|")[1:]
            out["why"].append(d)
        elif line.startswith("F558 ONE|"):
            d = fields(line)
            d["_t"] = line.rstrip("\n").split("|")[1:]
            out["one"].append(d)
        elif line.startswith("### sha256: "):
            out["kernel_sha"] = line.split(": ", 1)[1].strip()
    return out


def cells(L, env):
    got = {}
    for (o, l) in CELLS:
        arm = "g%d_%d" % (o, l)
        for key in ("run", "r557"):
            d = L[key].get((env, arm))
            if d:
                got[(o, l)] = int(d["cnt"]) - int(d["cnt0"])
                break
    return got


def ctl(L, env):
    d = L["run"].get((env, "ctl"))
    if d:
        return int(d["cnt"]) - int(d["cnt0"])
    d = L["ctl557"].get(env)
    if d:
        return int(d["cnt"]) - int(d["cnt0"])
    return None


def main():
    data = {
        "finding": "F36-vlan-envelope",
        "turn": 558,
        "question": (
            "Does the ip family ever see an 802.1Q tag at the link-layer hook, "
            "and what does an accepted LL store actually leave on the wire?"
        ),
        "answer_short": (
            "In the ip family the tag is gone from the frame by the hook in every "
            "envelope it can arrive in -- plain, vid 0, and through a real vlan "
            "device are the same 23/36 table, cell for cell; only the bridge "
            "family keeps the tag in metadata and gets 18. (16,2) rewrites the "
            "forwarded frame's ethertype (00->06 at byte 13); (14,2) and (12,4) "
            "change no frame byte and still decide the next hop's verdict."
        ),
        "logs": {}, "kernels": {}, "cells": {},
    }
    for k, src in (("T557", "src/linux-7.3.4-T557"),
                   ("T558", "src/linux-7.3.4-T558")):
        data["kernels"][k] = {
            "bzImage_sha256": sha(os.path.join(ROOT, src,
                                               "arch/x86/boot/bzImage")),
            "config_sha256": sha(os.path.join(ROOT, src, ".config")),
        }
    for tag in LOGS:
        L = parse(tag)
        data["logs"][tag] = {
            "kernel_sha256": L["kernel_sha"],
            "grid": {e: {"control": ctl(L, e),
                         "live": sum(1 for v in cells(L, e).values() if v),
                         "cells": {"%d_%d" % k: v
                                   for k, v in sorted(cells(L, e).items())}}
                     for e in ("p4", "novd", "vd", "novd2", "v0")
                     if cells(L, e)},
            "bytes": {a: {"counter": int(L["run"][("by", a)]["cnt"]) -
                          int(L["run"][("by", a)]["cnt0"]),
                          "ipin": int(L["run"][("by", a)]["ipin"]),
                          "nfl": int(L["run"][("by", a)]["nfl"]),
                          "tx_nchg": L["view"].get(("by", a, "tx"), {}).get("nchg"),
                          "tx_chg": L["view"].get(("by", a, "tx"), {}).get("chg"),
                          "rx_nchg": L["view"].get(("by", a, "rx"), {}).get("nchg"),
                          "rx_chg": L["view"].get(("by", a, "rx"), {}).get("chg"),
                          "tx_hex": L["view"].get(("by", a, "tx"), {}).get("hex", "")[:120]}
                      for a in BY if ("by", a) in L["run"]},
            "vlandev": [v.get("_raw") for v in L["vlandev"]],
            "one_send": [v.get("cnt_delta") for v in L["why"]
                         if "cnt_delta" in v],
        }
    # identities, computed rather than asserted
    ids = {}
    for tag in LOGS:
        L = parse(tag)
        p4, v0, vd = cells(L, "p4"), cells(L, "v0"), cells(L, "vd")
        ids[tag] = {"p4_eq_v0": p4 == v0, "p4_eq_vd": (p4 == vd) if vd else None,
                    "vd_eq_v0": (vd == v0) if vd else None}
    data["identities"] = ids
    data["one_send_ipv6"] = [
        {"run": x["_t"][0], "counts": x.get("cnt_delta"), "msgs": x.get("msgs")}
        for x in parse("ipv6_rep1")["one"] if "cnt_delta" in x]
    with open(os.path.join(ROOT, "findings/F36-vlan-envelope/summary.json"),
              "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)

    # ---------------- markdown tables ----------------
    print("<!-- generated by tools/f36_summary.py from "
          "logs/f36_{V_rep1,V_rep2,T_rep1}.log -->")
    print("")
    print("| envelope (ip family) | control | live/36 | same table as plain? |")
    print("|---|---|---|---|")
    for env, name in (("p4", "plain ethernet"),
                      ("v0", "802.1Q, vid 0 (priority tag)"),
                      ("vd", "802.1Q vid 100 through vlan device v1"),
                      ("novd", "802.1Q vid 100, no vlan device"),
                      ("novd2", "802.1Q vid 100, after v1 was deleted")):
        row = []
        for tag in ("V_rep1", "V_rep2", "T_rep1"):
            Lt = parse(tag)
            ct = cells(Lt, env)
            if not ct:
                row.append("—")
            elif ctl(Lt, env) == 0:
                row.append("n/a")          # the frame never arrives: a control
            else:
                row.append("%d/%d" % (sum(1 for v in ct.values() if v),
                                      len(ct)))
        L = parse("V_rep1")
        c = cells(L, env)
        same = "not measurable"
        if c and ctl(L, env) == 1:
            same = "yes" if c == cells(L, "p4") else "**no**"
        print("| %s | %s | %s | %s |" % (name, ctl(L, env), " / ".join(row),
                                         same))
    print("")
    print("| arm | what the rule does | counter | IpInReceives (far side) | "
          "frame bytes, tx tap | frame bytes, rx tap |")
    print("|---|---|---|---|---|---|")
    L = parse("V_rep1")
    for a in BY:
        b = data["logs"]["V_rep1"]["bytes"].get(a)
        if not b:
            continue
        chg = b["tx_chg"] if b["tx_chg"] not in (None, "-") else "unchanged"
        chg2 = b["rx_chg"] if b["rx_chg"] not in (None, "-") else "unchanged"
        print("| `%s` | %s | %d | +%d | `%s` | `%s` |"
              % (a, WHAT[a], b["counter"], b["ipin"], chg, chg2))
    print("")
    print("| boot | kernel | vlan device | one send -> counts / log messages |")
    print("|---|---|---|---|")
    for tag in LOGS:
        vd = [v for v in data["logs"][tag]["vlandev"] if "add_rc" in v]
        print("| %s | %s | `%s` | %s / %s |"
              % (tag, tag[0] == "V" and "T558 (+802.1Q)" or "T557",
                 vd[0] if vd else "—",
                 data["logs"][tag]["one_send"][0] if
                 data["logs"][tag]["one_send"] else "—",
                 [v for v in parse(tag)["why"]
                  if "cnt_delta" in v][0].get("msgs")))
    print("")
    print("| one send, IPv6 off and on again (boot `ipv6_rep1`) | "
          "counts | log messages | first bytes of every message |")
    print("|---|---|---|---|")
    L = parse("ipv6_rep1")
    runs = {}
    for x in L["one"]:
        nm = x["_t"][1]
        if nm.startswith("msg="):
            runs.setdefault(x["_t"][0], []).append(x["hex"][:24])
        else:
            runs.setdefault(x["_t"][0], [])
            runs[x["_t"][0] + "_d"] = (x.get("cnt_delta"), x.get("msgs"))
    for k in ("v6off", "v6on1", "v6on2", "v6off2"):
        d = runs.get(k + "_d", ("?", "?"))
        print("| `%s` | %s | %s | `%s` |"
              % (k, d[0], d[1], runs.get(k, ["—"])[0] if runs.get(k) else "—"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
