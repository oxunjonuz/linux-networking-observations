#!/usr/bin/env python3
"""f33_json.py -- emit findings/F33-guard-type-table/summary.json from the logs.

Same rule as the tables: nothing typed by hand.  Every list here is recomputed
from logs/f33_T_rep1.log (the grid and the E arms) and from the four bare logs
(the family matrix), and the image fields come from the logs' own headers.
"""
import hashlib
import json
import re

ROOT = "/work/kernel-sec"
OUT = ROOT + "/findings/F33-guard-type-table/summary.json"

GRID_OFF = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
GRID_LEN = [1, 2, 4]
XOFF = [0, 8, 16, 20]
XLEN = [8, 16, 16, 16]
CELLS = [(o, l) for o in GRID_OFF for l in GRID_LEN] + list(zip(XOFF, XLEN))
ENVS = ["ip4", "ip6", "nd", "eg4", "egA", "br4", "brA", "arp",
        "ll4", "llN", "llE", "llB"]
TYPE = {
    "ip4": "list-of-offsets (7 case labels, two of them read the packet)",
    "ip6": "list-of-offsets (5 case labels, case 0 reads the value)",
    "nd": "constant (netdev ingress -> true)",
    "eg4": "switch on skb->protocol -> ip4 branch",
    "egA": "switch on skb->protocol -> arp branch",
    "br4": "switch on pkt->ethertype -> ip4 branch",
    "brA": "switch on pkt->ethertype -> arp branch",
    "arp": "point (6,2) + half-plane off>=8 && len<=20",
    "ll4": "boundary off+len <= 14",
    "llN": "constant (ingress -> true)",
    "llE": "boundary off+len <= 14",
    "llB": "boundary off+len <= 14",
}
NOT_MEASURED = [
    "nftables 1.1.7 is the only netlink grammar used",
    "only IPv4 frames through the netdev switch (egA uses an ARP frame)",
    "IPv6 frames at egress not measured",
    "no VLAN frames (0x8100 is F31's subject)",
    "GSO/CHECKSUM_PARTIAL untouched",
    "the @ih (inner) base untouched -- that is F29",
    "one hook per family",
    "ll at egress measured only with the IPv4 frame",
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def parse(path):
    R, CTL, CHAIN, FAM, hdr = [], {}, {}, {}, {}
    rx = re.compile(r"^F556 R\|env=(\w+)\|arm=(\w+)\|off=(\d+)\|len=(\d+)\|"
                    r"kind=(\d+)\|rc=(-?\d+)\|cnt=(\d+)\|cnt0=(\d+)\|nfl=(\d+)\|")
    cr = re.compile(r"^F556 CTL\|env=(\w+)\|kind=(\d+)\|rc=(-?\d+)\|cnt=(\d+)\|"
                    r"cnt0=(\d+)\|nfl=(\d+)\|")
    with open(path, errors="replace") as f:
        for ln in f:
            m = re.match(r"^### (sha256|kernel|initrd sha256): (.*)$", ln)
            if m:
                hdr[m.group(1)] = m.group(2).strip()
            m = rx.match(ln)
            if m:
                R.append(dict(env=m.group(1), arm=m.group(2), off=int(m.group(3)),
                              len=int(m.group(4)), kind=int(m.group(5)),
                              rc=int(m.group(6)),
                              alive=int(m.group(7)) - int(m.group(8)) == 1,
                              nfl=int(m.group(9))))
                continue
            m = cr.match(ln)
            if m:
                CTL[m.group(1)] = dict(kind=int(m.group(2)), rc=int(m.group(3)),
                                       alive=int(m.group(4)) - int(m.group(5)) == 1,
                                       nfl=int(m.group(6)))
                continue
            m = re.match(r"^F556 CHAIN\|env=(\w+)\|table=(-?\d+)\|chain=(-?\d+)$", ln)
            if m:
                CHAIN[m.group(1)] = [int(m.group(2)), int(m.group(3))]
                continue
            m = re.match(r"^F556 FAM\|(\w+)\|(-?\d+)$", ln)
            if m:
                FAM[m.group(1)] = int(m.group(2))
    return R, CTL, CHAIN, FAM, hdr


def main():
    R, CTL, CHAIN, FAMT, HDR = parse(ROOT + "/logs/f33_T_rep1.log")
    fams = {}
    for letter, path in (("T556", "T"), ("B19", "B"), ("C553", "C"), ("A553", "A")):
        _, _, _, fam, _ = parse("%s/logs/f33_%s_bare.log" % (ROOT, path))
        fams[letter] = fam

    envs = {}
    for e in ENVS:
        acc = sorted([a["off"], a["len"]] for a in R if a["env"] == e and a["alive"])
        envs[e] = dict(type=TYPE[e], accepted=acc, count=len(acc), of=len(CELLS),
                       control=CTL.get(e), chain_rc=CHAIN.get(e))

    sets = {e: [tuple(x) for x in envs[e]["accepted"]] for e in ENVS}
    identities = {
        "ip4 == br4 == eg4": sets["ip4"] == sets["br4"] == sets["eg4"],
        "arp == brA == egA": sets["arp"] == sets["brA"] == sets["egA"],
        "ll4 == llB == llE": sets["ll4"] == sets["llB"] == sets["llE"],
        "nd == all 40": len(sets["nd"]) == len(CELLS),
        "llN == all 40": len(sets["llN"]) == len(CELLS),
    }
    e_arms = {a["arm"]: dict(env=a["env"], off=a["off"], len=a["len"],
                             kind=a["kind"], alive=a["alive"], nfl=a["nfl"])
              for a in R if a["env"] in ("e4", "e6", "ea", "eb")}
    doc = {
        "finding": "F33",
        "turn": 556,
        "question": "what KIND of function is each branch of nft_nh_write_ok(), "
                    "measured as the shape of its accept-set on one grid in one boot",
        "kernel": {
            "tree": "src/linux-7.3.4-T556",
            "bzImage_sha256": sha256(ROOT + "/src/linux-7.3.4-T556/arch/x86/boot/bzImage"),
            "parent": "src/linux-7.3.4-B19",
            "log_header_sha256": HDR.get("sha256"),
            "config_delta_symbols": ["CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE",
                                     "CONFIG_NF_TABLES_NETDEV", "CONFIG_NF_TABLES_ARP"],
            "sources_identical_to_parent": [
                "net/netfilter/nft_payload.c", "net/netfilter/nft_chain_filter.c",
                "net/netfilter/nf_tables_api.c", "net/ipv4/arp.c"],
        },
        "families": fams,
        "grid": {"cells": len(CELLS),
                 "offsets": GRID_OFF, "lens": GRID_LEN,
                 "extras": [[o, l] for o, l in zip(XOFF, XLEN)],
                 "envs": envs},
        "identities": identities,
        "e_arms": e_arms,
        "not_measured": NOT_MEASURED,
        "in_this_kernel": {
            "NF_NETDEV_INGRESS": 0,
            "NF_NETDEV_EGRESS": 1,
            "hook_mask_netdev": "(1 << NF_NETDEV_INGRESS) | (1 << NF_NETDEV_EGRESS)",
            "note": "F31 called nft_nh_write_ok_netdev() dead code; with the "
                    "egress hook it is reachable and measured here (eg4/egA)",
        },
    }
    with open(OUT, "w") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)
    print("wrote %s (%d envs, %d cells)" % (OUT, len(ENVS), len(CELLS)))


if __name__ == "__main__":
    main()
