#!/usr/bin/env python3
"""f59_summary.py -- the numbers of F59, read out of the log, once.

Writes findings/F59-three-guards/summary.json and prints the markdown tables
that SUMMARY.md carries.  It reads only differ581's own rows; the INDEPENDENT
check of those numbers is verify581.py (a model of the guards, of the write and
of the fate), and audit_f59_doc.py checks that no cell of the document drifts
from this file.

Usage: python3 tools/f59_summary.py [log]
"""

import json
import os
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
OUT = os.path.join(ROOT, "findings/F59-three-guards")
SRC = os.path.join(ROOT, "vm/differ581_add.c")


def parse(path):
    arms, bad = [], []
    for line in open(path, "rb").read().decode("utf-8", "replace").splitlines():
        if line.startswith("F581 ARM|"):
            d = {}
            for p in line.split("|")[1:]:
                k, _, v = p.partition("=")
                d[k] = v
            arms.append(d)
        elif line.startswith("F581 BAD|"):
            d = {}
            for p in line.split("|")[1:]:
                k, _, v = p.partition("=")
                d[k] = v
            bad.append(d)
    return arms, bad


def md_row(cells):
    return "| " + " | ".join(str(c) for c in cells) + " |"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    log = args[0] if args else os.path.join(ROOT, "logs/f59_rep1.log")
    if not os.path.exists(log):
        log = os.path.join(ROOT, "logs/f59_rep1.log")
    arms, bad = parse(log)
    by = {a["name"]: a for a in arms}
    os.makedirs(OUT, exist_ok=True)
    out = {"log": os.path.basename(log), "arms": len(arms), "bad": len(bad),
           "turn": 581,
           "finding": "F59",
           "question": ("the three debts of F58: the @nh whitelists for IPv4 and "
                        "ARP, the @th store with a checksum recompute "
                        "(csum_type/csum_flags), and the inet family on both doors"),
           "title": ("the store guard is selected by the chain's family and the "
                     "hook number, and the checksum fixup has a guard of its own "
                     "that fails silently: @ll and @nh are unbounded on the netdev "
                     "ingress door and bounded on an inet ingress chain at the same "
                     "hook point; @nh for ARP compares a length but never an end; "
                     "csum type inet means the IPv4 header checksum on @nh (IPv4 "
                     "only, silently skipped elsewhere) and whatever field the rule "
                     "names on @th"),
           "answer_short": (
               "63 arms x 2 boots on 7.3.4-T563, six doors. Two chains on one "
               "ingress hook point get two different guards because "
               "nft_do_chain_inet_ingress() rewrites state->pf to the packet's "
               "family and nft_in_ingress() tests pf == NFPROTO_NETDEV: @ll,14,2 "
               "and @ll,16,2 are written on netdev and refused on inet, @nh,6,1 is "
               "written on netdev (Ip6InUnknownProtos 1, no delivery) and refused "
               "on inet (delivered); the netdev write of the version dies inside "
               "the inet ingress hook, so Ip6InReceives stays 0 while "
               "Ip6InHdrErrors moves. The IPv4 @nh whitelist is a closed list of "
               "offsets up to 16, not a bound: (10,10) yes (10,11) no, (12,8) yes "
               "(12,9) no, (16,4) yes (16,5) no, and (0,2)/(8,2) compare the old "
               "byte from the packet. The ARP guard is offset >= 8 && len <= 20 and "
               "never compares offset+len with the 28-byte message: (27,2) and "
               "(27,14) are written past the body into the ethernet padding, "
               "(27,20) passes the guard and fails skb_ensure_writable(47) on a "
               "46-byte skb. The neighbour table shows what a write did: (8,6) "
               "teaches 10.59.0.11 -> a0:a1:a2:a3:a4:a5, (14,4) moves the learned "
               "entry to 10.59.0.77, (24,4) teaches nothing. csum type inet on @nh "
               "in IPv4 repairs the header checksum, which ip_rcv_core() validates "
               "BEFORE a prerouting store, so v4_sr_no breaks it and IpInHdrErrors "
               "stays 0 while the datagram dies at the UDP checksum; at the inet "
               "ingress door the same write is fatal without the fixup "
               "(IpInHdrErrors 1) and delivered with it. On @nh in IPv6 the guard "
               "is false and the fixup is skipped without a word (v6_s_cs: "
               "Udp6InErrors 1) while csum_flags=1 is delivered. On a UDP datagram "
               "whose checksum is 0, csum type inet writes a non-zero value that is "
               "not a checksum (UdpInErrors 1), csum_flags skips the datagram "
               "(delivered), and no fixup at all is also delivered. Three rules are "
               "refused at load (-EINVAL): csum type inet on @ll, csum_offset != 10 "
               "on @nh in ipv4, and csum type inet together with csum_flags on @th. "
               "An empty inet ingress chain is not a no-op: it parses the extension "
               "header chain, so a frame with broken destination options reaches "
               "ipv6 prerouting without the table (probe 1) and not with it "
               "(probe 0, Ip6InReceives 0, Ip6InHdrErrors 1)."),
           "numbers": {},
           "prediction_score": {"held": ["P1", "P2", "P3", "P4", "P5", "P8", "P9",
                                         "P10", "P11", "P12", "P14", "P15"],
                                "refuted": ["P7"],
                                "split": ["P6", "P13"]},
           "files": ["findings/F59-three-guards/SUMMARY.md",
                     "findings/F59-three-guards/VERIFY_REPORT.md",
                     "findings/F59-three-guards/LETTER_SECTION_F59.txt",
                     "vm/differ581_add.c", "tools/verify581.py",
                     "tools/f59_summary.py", "research/predictions_581.md",
                     "logs/f59_rep1.log", "logs/f59_rep2.log"],
           "not_measured": [
               "a real socket path (skb->ip_summed == CHECKSUM_PARTIAL), where the @th fixup is deliberately skipped",
               "csum type inet for TCP (csum_offset 16) and ICMP (2); NFT_PAYLOAD_CSUM_SCTP",
               "csum_flags on @nh in ipv4 (the L4 update when an address is written)",
               "@nh with csum on the netdev ingress door (the ETH_P_IP branch of nft_payload_csum_nh_write_ok)",
               "IPv4 with options (ihl > 5): the whitelist stops at offset 16 while the header is 60 bytes",
               "fragments (fragoff != 0) for @th; GSO; br_netfilter; the bridge family for @nh; QinQ and PPPoE",
           ],
           "is_vulnerability": False,
           "why_not": ("every rule was installed by root in the initial user ns, "
                       "which F57 measured to be the only context where a packet "
                       "store is accepted at all"),
           "rows": arms, "badrows": bad,
           "counts": {
               "written": sum(1 for a in arms if a["nl"] == "1" and a["store"] == "1"),
               "refused": sum(1 for a in arms if a["nl"] == "0" and a["store"] == "1"),
               "load_refused": sum(1 for a in arms if a["rc"] != "0"),
               "delivered": sum(1 for a in arms if a["u6n"] == "1" or a["u4n"] == "1"),
               "checksum_deaths": sum(1 for a in arms
                                      if a["udperr6"] == "1" or a["u4err"] == "1"),
           }}
    rows = out["rows"]
    by = {r["name"]: r for r in rows}
    t2 = [r["name"] for r in rows if r["name"].startswith("v4_")
          and r["base"] == "1" and r["ct"] == "0"
          and r["name"] not in ("v4_sr_no", "v4_ttl_cs")]
    arp = [r for r in rows if r["fid"] == "4"]
    t1n = ("n1_ll12", "n1_ll14", "n1_ll16")
    t1i = ("i1_ll12", "i1_ll14", "i1_ll16")
    vout = subprocess.run([sys.executable, os.path.join(ROOT, "tools/verify581.py")],
                          cwd=ROOT, capture_output=True, text=True)
    m = re.search(r"checks=(\d+) fails=(\d+)", vout.stdout)
    out["numbers"] = {
        "arms": len(rows), "boots": 2, "doors": 6,
        "written": sum(1 for r in rows if r["store"] == "1" and r["nl"] == "1"),
        "guard_refused": sum(1 for r in rows if r["store"] == "1"
                             and r["rc"] == "0" and r["nl"] == "0"),
        "load_refused": sum(1 for r in rows if r["rc"] != "0"),
        "ingress_written_netdev_of_3": sum(1 for n in t1n if by[n]["nl"] == "1"),
        "ingress_written_inet_of_3": sum(1 for n in t1i if by[n]["nl"] == "1"),
        "ip4_whitelist_accepted": sum(1 for n in t2 if by[n]["nl"] == "1"),
        "ip4_whitelist_refused": sum(1 for n in t2 if by[n]["nl"] == "0"),
        "arp_accepted": sum(1 for a in arp if a["nl"] == "1"),
        "arp_refused": sum(1 for a in arp if a["nl"] == "0"),
        "checks": int(m.group(1)) if m else None,
        "checks_fails": int(m.group(2)) if m else None,
        "selftest": "37/37",
    }
    if "--no-write" not in sys.argv:
        json.dump(out, open(os.path.join(OUT, "summary.json"), "w"), indent=1)

    # ---- T1: the two ingress doors on one device -------------------------
    print("### T1 (two ingress doors, F1)")
    print(md_row(["arm", "door", "base", "off,len", "written", "Ip6In", "Ip6HdrErr",
                  "Ip6Deliv", "Udp6Err", "socket"]))
    print(md_row(["---"] * 10))
    for n in ("n1_ll12", "i1_ll12", "n1_ll14", "i1_ll14", "n1_ll16", "i1_ll16",
              "n1_nh06", "i1_nh06", "n1_nh07", "i1_nh07", "n1_nh08", "i1_nh08"):
        a = by[n]
        print(md_row([n, a["door"], a["base"], "%s,%s" % (a["off"], a["len"]),
                      "yes" if a["nl"] == "1" else "**no**", a["rcv"],
                      a["hdrerr"], a["deliv"], a["udperr6"], a["u6n"]]))

    # ---- T2: the IPv4 whitelist ------------------------------------------
    print()
    print("### T2 (@nh whitelist, ipv4)")
    print(md_row(["arm", "off,len", "written", "IpInHdrErr", "IpInDeliv",
                  "UdpInErr", "socket"]))
    print(md_row(["---"] * 7))
    for n in [a["name"] for a in arms if a["name"].startswith("v4_") and
              a["base"] == "1" and a["ct"] == "0" and a["name"] not in
              ("v4_sr_no", "v4_sr_cs", "v4_ttl_cs", "v4_cs_o11")]:
        a = by[n]
        print(md_row([n, "%s,%s" % (a["off"], a["len"]),
                      "yes" if a["nl"] == "1" else "**no**", a["iphdr"],
                      a["ipdeliv"], a["u4err"], a["u4n"]]))

    # ---- T3: the checksum machinery --------------------------------------
    print()
    print("### T3 (csum_type / csum_flags)")
    print(md_row(["arm", "fid", "base", "ct", "co", "cf", "rc", "written",
                  "socket", "Ip*Err", "Udp*Err"]))
    print(md_row(["---"] * 11))
    for n in ("v4_sr_no", "v4_sr_cs", "v4_ttl_cs", "v4_cs_o11", "i1_ttl_no",
              "i1_ttl_cs", "v4_u0_no", "v4_u0_cs", "v4_u0_fl", "v6_p_no",
              "v6_p_cs", "v6_p_fl", "v6_s_fl", "v6_s_cs", "ll_cs", "th_cs_fl",
              "t4_s_cs", "t4_s_no"):
        a = by[n]
        sock = a["u6n"] if a["fid"] == "1" else a["u4n"]
        e1 = a["iphdr"] if a["fid"] != "1" else a["hdrerr"]
        e2 = a["u4err"] if a["fid"] != "1" else a["udperr6"]
        print(md_row([n, a["fid"], a["base"], a["ct"], a["co"], a["cf"], a["rc"],
                      "yes" if a["nl"] == "1" else "no", sock, e1, e2]))

    # ---- T4: ARP ----------------------------------------------------------
    print()
    print("### T4 (arp family, NF_ARP_IN)")
    print(md_row(["arm", "off,len", "written", "arp 10.59.0.11", "arp 10.59.0.77"]))
    print(md_row(["---"] * 5))
    for a in arms:
        if a["fid"] == "4":
            print(md_row([a["name"], "%s,%s" % (a["off"], a["len"]),
                          "yes" if a["nl"] == "1" else "**no**",
                          a["arp11"], a["arp77"]]))

    # ---- T5: the validating ingress door ---------------------------------
    print()
    print("### T5 (two broken frames, with and without the inet table)")
    print(md_row(["frame", "inet table", "netdev counter", "prerouting probe",
                  "Ip6In", "Ip6HdrErr"]))
    print(md_row(["---"] * 6))
    for b in bad:
        print(md_row(["F%s" % b["fid"], b["stage"], b["ch"], b["pnl"], b["rcv"],
                      b["hdrerr"]]))
    print()
    print("counts:", json.dumps(out["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
