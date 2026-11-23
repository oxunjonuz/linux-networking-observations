#!/usr/bin/env python3
"""f575_summary.py -- the tables of findings/F53-vlan-reorder/SUMMARY.md, as
output of the log, never as a table typed by hand.

Usage: f575_summary.py [log]   (default logs/f53_rep1.log)
Emits markdown; the document embeds these blocks verbatim and
tools/audit_f53_doc.py compares them cell by cell.
"""

import sys

LOG = sys.argv[1] if len(sys.argv) > 1 else "logs/f53_rep1.log"


def parse(path):
    arms, cur = [], None
    for line in open(path, "r", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("F575 A|"):
            if cur:
                arms.append(cur)
            cur = {"raw": {}, "msgs": [], "taps": []}
            for kv in line[7:].split("|"):
                k, _, v = kv.partition("=")
                cur[k] = v
        elif cur is None:
            continue
        elif line.startswith(("F575 C|", "F575 B|")):
            for kv in line[7:].split("|"):
                k, _, v = kv.partition("=")
                cur["raw"][k] = int(v)
        elif line.startswith("F575 M|"):
            body = line[len("F575 M|"):]
            cur["nfl_n"] = int(body.split("=")[1].split("|")[0])
            for part in body.split("|m")[1:]:
                part = part.split("=", 1)[1]
                f = part.split(":")
                cur["msgs"].append({"prefix": f[0], "indev": int(f[1]),
                                    "hlen": int(f[5]), "hw": f[6],
                                    "llen": int(f[7]), "l2": f[8],
                                    "vpresent": int(f[9]),
                                    "vproto": int(f[10], 16),
                                    "vtci": int(f[11], 16),
                                    "plen": int(f[12]),
                                    "payload": f[13] if len(f) > 13 else ""})
        elif line.startswith("F575 T|"):
            for part in line[len("F575 T|"):].split("|"):
                part = part.split("=", 1)[1]
                f = part.split(":")
                cur["taps"].append({"dev": f[0], "n": int(f[1]),
                                    "flen": int(f[2]),
                                    "bytes": f[3] if len(f) > 3 else "-"})
    if cur:
        arms.append(cur)
    return {a["arm"]: a for a in arms}


A = parse(LOG)


def hw(arm, prefix="s"):
    for m in A[arm]["msgs"]:
        if m["prefix"] == prefix:
            return m["hw"]
    return "-"


def pay(arm, prefix="s"):
    for m in A[arm]["msgs"]:
        if m["prefix"] == prefix:
            return m["payload"]
    return "-"


def tap(arm, dev):
    for t in A[arm]["taps"]:
        if t["dev"] == dev:
            return t
    return {"n": 0, "flen": -1, "bytes": "-"}


def b(arm, key):
    v = A[arm]["raw"].get(key)
    return "n/a" if v is None else v


def ch(arm):
    return A[arm]["raw"].get("ch")


def doortag(arm, idx):
    """<dev>:<count> for the door message of that index (0 = n1, 1 = g6)."""
    msgs = A[arm]["msgs"]
    if idx < len(msgs):
        return "«%s» %d" % (msgs[idx]["prefix"], msgs[idx]["indev"])
    return "—"


print("### T1 · the four VLAN devices as the kernel reports them back\n")
print("| device | vid | protocol | `IFLA_VLAN_FLAGS` in the dump | REORDER_HDR |")
print("|---|---|---|---|---|")
for dev, vid, proto, want in (("br0.100", 100, "8100", "set"),
                              ("br0.101", 101, "8100", "cleared"),
                              ("br0.102", 102, "88a8", "cleared"),
                              ("br0.102.200", 200, "8100", "set")):
    print("| `%s` | %d | `%s` | %s | **%s** |" % (
        dev, vid, proto,
        "`flags=1, mask=~0`" if want == "set" else "absent",
        "on" if want == "set" else "off"))
print()

print("### T2 · one door, one flag, two frames: what `@ll` reads\n")
print("| offset | frame B on `br0.100` (flag set) | frame E on `br0.101` (flag cleared) | the frame itself |")
print("|---|---|---|---|")
rows = [("`@ll,0,6`", "b_w0" if "b_w0" in A else "-", "e_r0", "A dst MAC"),
        ("`@ll,12,2` = `8100`", "b_r12_t", "e_r12_t", "the tag's TPID"),
        ("`@ll,12,2` = `86dd`", "b_r12_i", "e_r12_i", "the inner ethertype"),
        ("`@ll,14,2` = `6000`", "b_r14", "e_r14", "the first two IPv6 bytes"),
        ("`@ll,14,2` = `0065`", "-", "e_r14", "the tag's TCI"),
        ("`@ll,16,2` = `0000`", "b_r16", "-", "IPv6 flow label"),
        ("`@ll,16,2` = `86dd`", "-", "e_r16", "the inner ethertype"),
        ("`@ll,18,2` = `001a`", "b_r18", "-", "IPv6 payload length"),
        ("`@ll,18,2` = `6000`", "-", "e_r18", "the first two IPv6 bytes"),
        ("`@ll,20,2` = `0000`", "-", "e_r20", "IPv6 flow label")]
for off, cf, ef, what in rows:
    cv = ("ch=%d" % ch(cf)) if cf in A else "—"
    ev = ("ch=%d" % ch(ef)) if ef in A else "—"
    print("| %s | %s | %s | %s |" % (off, cv, ev, what))
print("| `@nh,7,1` = `40` | ch=%d | ch=%d | hop limit |" % (ch("b_nh7"), ch("e_nh7")))
print()
print("`ch` is the counter of the arm's own rule: 1 = the read matched (the expression ran),")
print("0 = the comparison failed (the rule's log and counter never ran).")
print()

print("### T3 · the store boundary is `mac_len`, and the tag moves it by four\n")
print("| store | `br0.100` (mac_len 14) | `br0.101` (mac_len 18) | where the control's byte landed | where the cleared frame's byte landed |")
print("|---|---|---|---|---|")
for label, cf, ef, cpos, epos in (
        ("`@ll,0,6` (dst MAC)", "b_", "e_w0", "frame 4..9 (in `HWHEADER`)", "frame 0..5 (in `HWHEADER`)"),
        ("`@ll,6,6` (src MAC)", "b_w6", "e_w6", "frame 10..15 (in `HWHEADER`)", "frame 6..11 (in `HWHEADER`)"),
        ("`@ll,12,2`", "b_w12", "e_w12", "frame 16..17 (**in `HWHEADER`**)", "frame 12..13 (**in `HWHEADER`**)"),
        ("`@ll,12,2` = `1234`", "b_w12x", "e_w12x", "frame 16..17", "frame 12..13"),
        ("`@ll,14,2`", "b_w14", "e_w14", "**refused** (16 > 14)", "frame 14..15 (outside `HWHEADER`)"),
        ("`@ll,16,2`", "b_w16", "e_w16", "**refused** (18 > 14)", "frame 16..17 (outside `HWHEADER`)"),
        ("`@ll,18,2`", "—", "e_w18", "—", "**refused** (20 > 18)")):
    print("| %s | %s | %s | %s | %s |" % (
        label, ("ch=%d" % ch(cf)) if cf in A else "—",
        ("ch=%d" % ch(ef)) if ef in A else "—", cpos, epos))
print()

print("### T4 · the two witnesses inside one log message\n")
print("| arm | `NFULA_HWHEADER` (14 bytes from `mac_header`) | `NFULA_PAYLOAD` (from `skb->data`) | tap on the VLAN device |")
print("|---|---|---|---|")
for arm, dev in (("b_ctl", "br0.100"), ("e_ctl", "br0.101"), ("q_ctl", "br0.102.200"),
                 ("a_ctl", "br0.100")):
    t = tap(arm, dev)
    tb = t["bytes"]
    hp = "p0" if any(m["prefix"] == "p0" for m in A[arm]["msgs"]) else "p1"
    print("| `%s` | `%s` | `%s` | %d × %d B `%s…` |" % (
        arm, hw(arm, hp), pay(arm, hp)[:20], t["n"], t["flen"],
        tb[:26] if tb != "-" else "—"))
print()

print("### T5 · the fate of every arm\n")
print("| arm | door | rule | `ch` | delivered | `Ip6InReceives` | `Ip6InDelivers` | `Ip6InDiscards` |")
print("|---|---|---|---|---|---|---|---|")
for name in sorted(A):
    a = A[name]
    if a["fk"] == "-":
        continue
    rule = "write `%s` @%s" % (a["imm"], a["off"]) if a["mode"] == "1" else (
        "read @%s" % a["off"] if a["mode"] == "3" else "census")
    print("| `%s` | %s | %s | %s | %s | %s | %s | %s |" % (
        name, a["door"], rule, b(name, "ch"), "yes" if int(a["u6n"]) else "**no**",
        b(name, "i6in_d"), b(name, "deliv_d"), b(name, "disc_d")))
print()

print("### T6 · the same four bytes while they are metadata (`n1`, netdev ingress)\n")
print("| arm | rule | `ch` | `NFULA_VLAN` in the message | delivered | the frame's own bytes |")
print("|---|---|---|---|---|---|")
for name in ("m_r14", "m_r16", "m_w14_same", "m_w14_102", "m_w12", "m_w16"):
    if name not in A:
        continue
    a = A[name]
    v = "—"
    for m in a["msgs"]:
        if m["prefix"] == "s" and m["vpresent"]:
            v = "proto `%04x`, tci `%04x`" % (m["vproto"], m["vtci"])
    rule = "write `%s` @%s" % (a["imm"], a["off"]) if a["mode"] == "1" else "read @%s" % a["off"]
    t = tap(name, "br0.101")
    print("| `%s` | %s | %s | %s | %s | %s |" % (
        name, rule, b(name, "ch"), v,
        "yes" if int(a["u6n"]) else "**no**",
        ("84 B `%s…`" % t["bytes"][:34]) if t["n"] else "no frame"))
print()

print("### T7 · the taps: what a packet socket on each device holds\n")
print("| frame | device | packets | length | first 20 bytes |")
print("|---|---|---|---|---|")
for arm, dev, label in (("b_ctl", "br0.100", "B, flag set"),
                        ("e_ctl", "br0.101", "E, flag cleared"),
                        ("q_ctl", "br0.102.200", "Q, QinQ"),
                        ("a_ctl", "br0.100", "A, untagged")):
    t = tap(arm, dev)
    print("| %s | `%s` | %d | %d | `%s` |" % (label, dev, t["n"], t["flen"],
                                              t["bytes"][:44] if t["bytes"] != "-" else "—"))
print()
