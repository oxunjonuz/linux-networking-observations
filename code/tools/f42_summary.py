#!/usr/bin/env python3
"""f42_summary.py -- build summary.json and the markdown tables of F42 from
the log.  The document's numbers are DERIVED here and then checked back
against the log by audit_f42_doc.py -- a separate program, because the tool
that prints a table is the last thing that should be trusted to check it.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "v564", os.path.join(os.path.dirname(os.path.abspath(__file__)), "verify564.py"))
V = importlib.util.module_from_spec(spec)
src = open(spec.origin).read().replace('if __name__ == "__main__":\n    sys.exit(main())', '')
exec(compile(src, spec.origin, "exec"), V.__dict__)

LOGS = os.environ.get(
    "F42_LOGS",
    "/work/kernel-sec/logs/f42_rep1.log,/work/kernel-sec/logs/f42_rep2.log").split(",")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "-"
    t = V.text(LOGS[0])
    ln = V.lines_of(t)
    B = [V.kv(x) for x in ln if x.startswith("F564 B|")]
    Vv = [V.kv(x) for x in ln if x.startswith("F564 V|")]
    Ll = [V.kv(x) for x in ln if x.startswith("F564 L|")]

    rows_b = []
    for d in B:
        rows_b.append({
            "arm": d["arm"], "gate": V.num(d, "gate"), "base": V.num(d, "base"),
            "off": V.num(d, "off"), "len": V.num(d, "len"),
            "live": V.num(d, "live"), "ipin": V.num(d, "ipin"),
            "ihdr": V.num(d, "ihdr"), "iaddr": V.num(d, "iaddr"),
            "ideliv": V.num(d, "ideliv"), "prx": V.num(d, "prx"),
            "prp": V.num(d, "prp"), "udp4": V.num(d, "udp4"),
            "urn": V.num(d, "urn"), "crn": V.num(d, "crn"),
            "rn": V.num(d, "rn"), "rhex": d.get("rhex"), "uhex": d.get("uhex"),
            "what": d.get("what"),
        })
    rows_v = []
    for d in Vv:
        rows_v.append({
            "arm": d["arm"], "off": V.num(d, "off"), "len": V.num(d, "len"),
            "live": V.num(d, "live"), "i6in": V.num(d, "i6in"),
            "i6hdr": V.num(d, "i6hdr"), "i6addr": V.num(d, "i6addr"),
            "i6deliv": V.num(d, "i6deliv"), "prx": V.num(d, "prx"),
            "urn": V.num(d, "urn"), "udp6": V.num(d, "udp6"),
            "rhex": d.get("rhex"), "urhex": d.get("urhex"),
            "what": d.get("what"),
        })
    rows_l = []
    for d in Ll:
        if "arm" not in d:
            continue
        rows_l.append({
            "pass": d.get("pass"), "arm": d["arm"], "off": V.num(d, "off"),
            "len": V.num(d, "len"), "live": V.num(d, "live"),
            "arc": V.num(d, "arc"), "repn": V.num(d, "repn"),
            "rephex": d.get("rephex"), "ent": d.get("ent"),
            "what": d.get("what"),
        })

    frame = V.hx(V.kv([x for x in ln if x.startswith("F564 FRAME|ps|")][0])["wire"])
    v6frame = V.hx(V.kv([x for x in ln if x.startswith("F564 V6|frame|")][0])["wire"])

    js = {
        "turn": 564,
        "finding": "F42",
        "question": "Does a bridge @nh write reach a real IP stack through PPPoE "
                    "in the PPPOX_BOUND state, what does IPv6 inside PPPoE do to "
                    "the same white list, and does an ARP frame with vid 100 "
                    "arrive once a real vlan device exists?",
        "answer_short": "Yes to the first: with a real unit "
                        "(PPPIOCNEWUNIT/ATTCHAN/CONNECT, no pppd) the datagram "
                        "written from the bridge arrives at a UDP socket on ppp0 "
                        "with its 18 payload bytes, but every accepted ip4 cell "
                        "lands eight bytes before the field it names, inside the "
                        "bytes the IP header checksum covers, so the receiving "
                        "stack drops them as IpInHdrErrors while the five refused "
                        "cells leave the frame byte-identical to the control (a "
                        "refusal is not a drop). @ll rewrites the source MAC (the "
                        "session lookup then fails) and the ethertype byte (the "
                        "wire changes, the dispatch does not: the same bytes from "
                        "outside are not PPPoE at all). In the ip6 list the "
                        "hop_limit cell lands on the PPP protocol's low byte, "
                        "0x0057 becomes 0x0090, the frame goes to the pppd unit "
                        "queue while ppp0 still counts 66 bytes as received. And "
                        "the same vid-100 ARP frame reaches NF_ARP_IN only when a "
                        "vlan device exists: 0 without it, 1 with it, a 42-byte "
                        "reply and /proc/net/arp naming v1.",
        "kernel": "7.3.4-T563",
        "kernel_sha256": "1efbc95771acb424ec876dfa5c32ff1e993f5230b840c27ff00125978cbd2033",
        "arms_per_boot": len(B) + len(Vv) + len(rows_l),
        "frame_ps": frame.hex(),
        "frame_v6": v6frame.hex(),
        "bound": rows_b,
        "v6p": rows_v,
        "vlan": rows_l,
    }
    body = json.dumps(js, indent=1, sort_keys=True)
    if out == "-":
        print(body)
    else:
        open(out, "w").write(body + "\n")
        print("wrote %s (%d bytes)" % (out, len(body)))


if __name__ == "__main__":
    main()
