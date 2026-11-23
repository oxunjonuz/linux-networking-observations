#!/usr/bin/env python3
"""f33_summary.py -- derive the F33 tables FROM the logs, never by hand.

Every number this turn puts in SUMMARY.md is printed here, from the same log
lines the verifier reads, so the document and the check cannot drift apart in
different directions.  The three tables it emits are marked with HTML comments
(F33T1..F33T3) and audit_f33_doc.py rebuilds them cell by cell.

Usage: python3 tools/f33_summary.py [T_rep1]
"""
import re
import sys

ROOT = "/work/kernel-sec"
GRID_OFF = [0, 1, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24]
GRID_LEN = [1, 2, 4]
XOFF = [0, 8, 16, 20]
XLEN = [8, 16, 16, 16]
CELLS = [(o, l) for o in GRID_OFF for l in GRID_LEN] + list(zip(XOFF, XLEN))
ENVS = ["ip4", "ip6", "nd", "eg4", "egA", "br4", "brA", "arp",
        "ll4", "llN", "llE", "llB"]
TYPE = {
    "ip4": "список точек с длиной (7 `case`), два из них читают пакет",
    "ip6": "список точек с длиной (5 `case`), `case 0` читает значение",
    "nd": "константа: `ingress` -> true",
    "eg4": "переключатель по `skb->protocol` -> ветвь ip4",
    "egA": "переключатель по `skb->protocol` -> ветвь arp",
    "br4": "переключатель по метке -> ветвь ip4",
    "brA": "переключатель по метке -> ветвь arp",
    "arp": "точка (6,2) + полуплоскость `off>=8 && len<=20`",
    "ll4": "граница: `off+len <= 14`",
    "llN": "константа: `ingress` -> true",
    "llE": "граница: `off+len <= 14`",
    "llB": "граница: `off+len <= 14`",
}
E_ROWS = ["ip4_0_2_ihl5", "ip4_0_2_ihl6", "ip4_8_2_p17", "ip4_8_2_p6",
          "ip6_0_4_v6_a", "ip6_0_4_v6_b", "ip6_0_4_v4_a", "ip6_0_4_v4_b",
          "arp_fam_arpframe", "arp_fam_ipv4frame", "br_6_2_ip", "br_6_2_arp",
          "br_6_4_arp"]
E_WHAT = {
    "ip4_0_2_ihl5": ("IPv4 ihl 5, байт 14 = 0x45", "0x45 0x91"),
    "ip4_0_2_ihl6": ("IPv4 ihl 6, байт 14 = 0x46", "0x45 0x91"),
    "ip4_8_2_p17": ("IPv4 proto 17, байт 23 = 0x11", "ttl 0x90, 0x11"),
    "ip4_8_2_p6": ("IPv4 proto 6, байт 23 = 0x06", "ttl 0x90, 0x11"),
    "ip6_0_4_v6_a": ("IPv6 кадр A", "0x60000000"),
    "ip6_0_4_v6_b": ("IPv6 кадр B (др. tc/hoplimit)", "0x60000000"),
    "ip6_0_4_v4_a": ("IPv6 кадр A", "0x40000000"),
    "ip6_0_4_v4_b": ("IPv6 кадр B", "0x40000000"),
    "arp_fam_arpframe": ("ARP-кадр", "0x90 0x11"),
    "arp_fam_ipv4frame": ("IPv4-кадр в семействе arp", "0x90 0x11"),
    "br_6_2_ip": ("мост, метка 0x0800", "0x90 0x11"),
    "br_6_2_arp": ("мост, метка 0x0806", "0x90 0x11"),
    "br_6_4_arp": ("мост, метка 0x0806", "0x90 0x91 0x92 0x93"),
}


def parse(path):
    R, CTL, CHAIN, FAM = [], {}, {}, {}
    with open(path, "rb") as f:
        for line in f.read().decode("utf-8", "replace").splitlines():
            m = re.match(r"^F556 R\|env=(\w+)\|arm=(\w+)\|off=(\d+)\|len=(\d+)\|"
                         r"kind=(\d+)\|rc=(-?\d+)\|cnt=(\d+)\|cnt0=(\d+)\|"
                         r"nfl=(\d+)\|(?:ms=[0-9,]+\|)?hex=", line)
            if m:
                R.append(dict(env=m.group(1), arm=m.group(2), off=int(m.group(3)),
                              len=int(m.group(4)), kind=int(m.group(5)),
                              rc=int(m.group(6)), cnt=int(m.group(7)) - int(m.group(8)),
                              nfl=int(m.group(9))))
                continue
            m = re.match(r"^F556 CTL\|env=(\w+)\|kind=(\d+)\|rc=(-?\d+)\|cnt=(\d+)\|"
                         r"cnt0=(\d+)\|nfl=(\d+)", line)
            if m:
                CTL[m.group(1)] = dict(kind=int(m.group(2)), rc=int(m.group(3)),
                                       cnt=int(m.group(4)) - int(m.group(5)),
                                       nfl=int(m.group(6)))
                continue
            m = re.match(r"^F556 FAM\|(\w+)\|(-?\d+)$", line)
            if m:
                FAM[m.group(1)] = int(m.group(2))
    return R, CTL, FAM


def acc(R, env):
    return sorted((a["off"], a["len"]) for a in R if a["env"] == env and a["cnt"] == 1)


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "T_rep1"
    R, CTL, FAM = parse("%s/logs/f33_%s.log" % (ROOT, tag))
    print("<!-- F33T1 -->")
    print("| конверт | тип (из исходника) | принято | клетки |")
    print("|---|---|---|---|")
    for env in ENVS:
        s = acc(R, env)
        cells = " ".join("(%d,%d)" % c for c in s)
        print("| `%s` | %s | **%d/40** | `%s` |" % (env, TYPE[env], len(s), cells))
    print()
    print("<!-- F33T2 -->")
    sel = [(0, 2), (0, 4), (1, 1), (6, 2), (8, 4), (12, 4), (14, 1),
           (16, 16), (24, 4)]
    print("| клетка | " + " | ".join(ENVS) + " |")
    print("|---|" + "---|" * len(ENVS))
    for c in sel:
        row = []
        for env in ENVS:
            a = [x for x in R if x["env"] == env and x["off"] == c[0] and x["len"] == c[1]]
            row.append(str(a[0]["cnt"]) if a else "-")
        print("| `(%d,%d)` | %s |" % (c[0], c[1], " | ".join(row)))
    print()
    print("<!-- F33T3 -->")
    print("| плечо | что меняется | записываем | cnt |")
    print("|---|---|---|---|")
    for arm in E_ROWS:
        a = [x for x in R if x["arm"] == arm]
        what, val = E_WHAT[arm]
        print("| `%s` | %s | `%s` | %s |" % (arm, what, val,
                                             a[0]["cnt"] if a else "-"))
    print()
    print("families: " + " ".join("%s=%d" % (k, v) for k, v in sorted(FAM.items())))
    print("controls: " + " ".join("%s(cnt=%d,nfl=%d)" % (k, v["cnt"], v["nfl"])
                                  for k, v in sorted(CTL.items())))
    print("arms: %d" % len(R))


if __name__ == "__main__":
    main()
