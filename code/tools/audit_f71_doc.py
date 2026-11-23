#!/usr/bin/env python3
"""audit_f71_doc.py -- does findings/F71-condense-clause1/SUMMARY.md still say
what the logs say?

Every number the document quotes is looked up, independently of the document, in
the log lines (parsed here with plain regexes, not through the verifier's
parser).  With --mutate the document is copied, ONE substitution is applied, and
the audit must go RED: a check that cannot be made to fail is not a check.

Usage: audit_f71_doc.py [--mutate CASE]
"""
import json
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F71-condense-clause1/SUMMARY.md"
SJ = ROOT + "/findings/F71-condense-clause1/summary.json"
LOGS = [ROOT + "/logs/f71_rep1.log", ROOT + "/logs/f71_rep2.log"]

PASS = 0
FAIL = 0
FAILS = []


def ck(cond, what, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        FAILS.append("%s %s" % (what, detail))


def cells(logs_text):
    """(arm, attempt) -> {'cnt': {...}, 'eq': {...}, 'cq': {...}, 'rcv': {...}}
    straight from the log, by each line's own i=/att= fields"""
    out = {}
    for ln in logs_text.splitlines():
        m = re.match(r"F593 (CNT|EQ|CQ|RCV)\|i=(\d+)\|att=(\d+)\|(.*)$", ln)
        if not m:
            continue
        kind, i, att, rest = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
        d = {}
        for part in rest.split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                d[k] = v
        out.setdefault((i, att), {})[kind] = d
    return out


def audit(doc, logs_text, sj):
    def has(s, what):
        ck(s in doc, "doc/" + what, s[:70])

    C = cells(logs_text)
    # the six-datagram aggregate at the gate, in the log and in the doc
    eq = C[(1, 0)]["EQ"]
    cq = C[(1, 0)]["CQ"]
    ck(eq["ts"] == "7680" and eq["dlen"] == "2560" and eq["len"] == "3072"
       and eq["tail"] == "556" and eq["end"] == "704" and eq["fl"] == "0",
       "log/pg6-gate", str(eq))
    ck(eq == cq, "log/gate-eq-branch", "%s %s" % (eq, cq))
    has("f593enq:  len=3072 dlen=2560 tail=556 end=704 ts=7680 fl=0",
        "pg6-record-enq")
    has("f593cond: len=3072 dlen=2560 tail=556 end=704 ts=7680 fl=0",
        "pg6-record-cond")
    has("7680 = 6 × 1280", "pg6-sum")

    # the byte boundaries: for each head, room, pull arms, return arm, price
    bound = [
        # head, end, tail, room, pulls, returns, price
        (512, 704, 556, 148, "147, **148**", "**149**", 1280, (2, 3, 4)),
        (200, 384, 244, 140, "139, **140**", "**141**", 960, (7, 8, 9)),
        (1200, 1728, 1244, 484, "483, **484**", "**485**", 2304, (10, 11, 12)),
    ]
    for head, end, tail, room, pulls, rets, price, (ai, bi, ci) in bound:
        e = C[(ai, 0)]["CQ"]
        ck(int(e["end"]) == end and int(e["tail"]) == tail, "log/geom-%d" % head,
           str(e))
        ck(int(C[(ai, 0)]["CNT"]["pull"]) == 1, "log/pull-%d" % head, "")
        ck(int(C[(ci, 0)]["CNT"]["pull"]) == 0, "log/return-%d" % head, "")
        ck(int(C[(ai, 0)]["RCV"]["rmem1"]) - 16 * 1280 == price,
           "log/price-%d" % head, C[(ai, 0)]["RCV"]["rmem1"])
        row = "| %d | %d | %d | **%d** | %s | %s | **%d** = %d + 576 |" % (
            head, end, tail, room, pulls, rets, price, end)
        has(row, "boundary-row-%d" % head)

    # the inversion: the same pair below and above half
    lo = C[(6, 0)]["RCV"]["rmem1"]
    hi = C[(3, 0)]["RCV"]["rmem1"]
    ck(int(lo) - 0 == 2240 and int(hi) - 16 * 1280 == 1280, "log/inversion",
       "%s %s" % (lo, hi))
    has("| `g_t512_lo` | 0 | 148 | 0 calls | — | **2240** |", "inv-row-lo")
    has("| `g_t512_148` | 16 | 148 | 1 call | 148 bytes | **1280** |",
        "inv-row-hi")

    # the tap cell
    t = C[(5, 0)]
    n = C[(2, 0)]
    ck(t["CQ"]["fl"] == "1" and t["CNT"]["pull"] == "0", "log/tap-cloned",
       str(t["CNT"]))
    ck(n["CQ"]["fl"] == "0" and n["CNT"]["pull"] == "1", "log/notap-pull",
       str(n["CNT"]))
    ck(int(t["RCV"]["rmem1"]) - 16 * 1280 == 2240, "log/tap-charge", "")
    ck(int(n["RCV"]["rmem1"]) - 16 * 1280 == 1280, "log/notap-charge", "")
    has("| `g_t512_147` | closed | **0** | **0** | **1** (`eat=147`) | **1280** |",
        "tap-row-closed")
    has("| `g_t512_147t` | open | **1** | 5 / 2 (both boots) | **0** | **2240** |",
        "tap-row-open")

    # the fraglist on a UDP_GRO socket
    f = C[(13, 0)]["CNT"]
    ck(f["enq"] == "6" and f["cond"] == "6" and f["seg"] == "1", "log/flgro", str(f))
    has("| `g_fl_gro` | fraglist | **UDP_GRO** | **6** | **1** | 6 × 512 | 7680 |",
        "flgro-row")
    has("| `g_pg_pl` | linear | plain | 6 | 0 | 6 × 512 | 7680 |", "pgpl-row")

    # the single datagram
    one = C[(16, 0)]
    ck(one["EQ"]["dlen"] == "0" and one["EQ"]["ts"] == "1280", "log/one",
       str(one["EQ"]))
    has("`g_pg1_gro`: one datagram of 512 through the linear door — `dlen = 0`",
        "one-row")

    # the record counts the document quotes
    for path in LOGS:
        t = open(path, encoding="utf-8", errors="replace").read()
        ne = len(re.findall(r"f593enq:", t))
        nc = len(re.findall(r"f593cond:", t))
        npull = len(re.findall(r"f593pull:", t))
        ck(ne == 66 and nc == 62 and npull == 12, "log/record-counts",
           "%s %d/%d/%d" % (os.path.basename(path), ne, nc, npull))
    has("in every one of the 66 enqueue records each boot printed", "count-eq")
    has("62 condense records", "count-cq")

    # the counts of the turn
    ck(len(C) == 36, "log/attempts", str(len(C)))
    ck(len(sj["boots"]) == 2 and all(len(b["arms"]) == 18 for b in sj["boots"]),
       "sj/attempts", str([len(b["arms"]) for b in sj["boots"]]))
    has("**18 arms × 2 attempts × 2 boots = 72 attempts**", "count-attempts")
    has("**3936 checks, 0**", "count-checks")
    has("**20/20**", "count-selftest")
    src = open(ROOT + "/tools/verify593.py", encoding="utf-8").read()
    blk = src.split("SRC_ANCHORS = [", 1)[1].split("\n]", 1)[0]
    nanchor = len(re.findall(r'^\s*\("', blk, re.M))
    ck(nanchor == 21, "src/anchor-count", str(nanchor))
    has("%d source anchors" % nanchor, "count-anchors")
    add_src = open(ROOT + "/vm/differ593_add.c", encoding="utf-8").read()
    nprobe = add_src.count('"p:f593')
    ck(nprobe == 7, "src/probe-count", str(nprobe))
    has("Seven kprobes", "count-probes")
    has("| each boot alone | **1890 / 0** and **1890 / 0** |", "count-per-boot")

    # the arm table in summary.json must agree with the log on the cells quoted
    for b in sj["boots"]:
        for a in b["arms"]:
            if a["name"] == "g_t512_148":
                ck(a["measured"]["pull"] == 1 and a["measured"]["charge"] == 1280,
                   "sj/t512_148", str(a["measured"]))
            if a["name"] == "g_pg6_gt":
                ck(a["measured"]["charge"] == 7680 and a["branch"]["dlen"] == 2560,
                   "sj/pg6", str(a["measured"]))
            if a["name"] == "g_t1200_485":
                ck(a["measured"]["pull"] == 0 and a["measured"]["charge"] == 3584,
                   "sj/t1200_485", str(a["measured"]))


def main():
    doc = open(DOC, encoding="utf-8").read()
    logs_text = "\n".join(open(p, encoding="utf-8", errors="replace").read()
                          for p in LOGS)
    sj = json.load(open(SJ))
    if len(sys.argv) > 2 and sys.argv[1] == "--mutate":
        case = sys.argv[2]
        subs = {
            "pg6-ts": ("f593enq:  len=3072 dlen=2560 tail=556 end=704 ts=7680",
                       "f593enq:  len=3072 dlen=2560 tail=556 end=704 ts=6400"),
            "room148": ("| 512 | 704 | 556 | **148** | 147, **148** | **149** | "
                        "**1280** = 704 + 576 |",
                        "| 512 | 704 | 556 | **149** | 147, **148** | **149** | "
                        "**1280** = 704 + 576 |"),
            "price960": ("| 200 | 384 | 244 | **140** | 139, **140** | "
                         "**141** | **960** = 384 + 576 |",
                         "| 200 | 384 | 244 | **140** | 139, **140** | "
                         "**141** | **1280** = 384 + 576 |"),
            "inversion": ("| `g_t512_148` | 16 | 148 | 1 call | 148 bytes | "
                          "**1280** |",
                          "| `g_t512_148` | 16 | 148 | 1 call | 148 bytes | "
                          "**2240** |"),
            "tap-closed": ("| `g_t512_147` | closed | **0** | **0** | "
                           "**1** (`eat=147`) | **1280** |",
                           "| `g_t512_147` | closed | **1** | **0** | "
                           "**1** (`eat=147`) | **1280** |"),
            "flgro": ("| `g_fl_gro` | fraglist | **UDP_GRO** | **6** | **1** | "
                      "6 × 512 | 7680 |",
                      "| `g_fl_gro` | fraglist | **UDP_GRO** | **1** | **0** | "
                      "6 × 512 | 7680 |"),
            "attempts": ("**18 arms × 2 attempts × 2 boots = 72 attempts**",
                         "**18 arms × 2 attempts × 2 boots = 36 attempts**"),
            "checks": ("**3936 checks, 0**", "**3937 checks, 0**"),
            "selftest": ("**20/20**", "**19/20**"),
            "sum": ("7680 = 6 × 1280", "7680 = 5 × 1280"),
        }
        if case not in subs:
            print("unknown case", case)
            return 2
        old, new = subs[case]
        if doc.count(old) != 1:
            print("SAMPLE_NOT_FOUND", case, doc.count(old))
            return 2
        audit(doc.replace(old, new), logs_text, sj)
        print("mutated %s: %d checks, %d failed" % (case, PASS, FAIL))
        for f in FAILS[:6]:
            print("  FAIL:", f)
        return 1 if FAIL else 0
    audit(doc, logs_text, sj)
    print("audit_f71_doc: %d checks, %d failed" % (PASS, FAIL))
    for f in FAILS[:20]:
        print("FAIL:", f)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
