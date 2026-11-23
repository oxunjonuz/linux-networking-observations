#!/usr/bin/env python3
"""audit_f38_doc.py -- does SUMMARY.md still say what the logs say?

Every table cell in findings/F38-recv-side-of-the-tag/SUMMARY.md is re-derived
from summary.json (which f38_summary.py derives from the two counted logs) and
compared.  A NUMBER IN THE DOCUMENT THAT DOES NOT COME FROM A LOG IS A BUG, and
this script is how that rule is enforced instead of intended.

usage: audit_f38_doc.py [FILE]
       audit_f38_doc.py --selftest     change one cell in a copy and require
                                      the audit to notice it
"""
import json
import re
import subprocess
import sys

ROOT = "/work/kernel-sec"
DOC = ROOT + "/findings/F38-recv-side-of-the-tag/SUMMARY.md"
JSON = ROOT + "/findings/F38-recv-side-of-the-tag/summary.json"
LOG = ROOT + "/logs/f38_rep1.log"

ALIAS = {
    "голый (`p`)": "recv.p",
    "0x8100 vid 100 в байтах (`w100`)": "recv.w100",
    "«метка, поставленная правилом» (`m100`)": "recv.m100",
    "0x8100 vid 0 в байтах (`v0`)": "recv.v0",
    "0x9100 + те же четыре байта (`x91`)": "recv.x91",
    "голый": "ndin.p",
    "0x8100 в байтах": "ndin.w100",
    "0x9100 в байтах": "ndin.x91",
    "`0x0800`": "ndeg.s0800",
    "`0x8100`": "ndeg.s8100",
    "`0x9100`": "ndeg.s9100",
    "голый ARP": "arp.a",
    "0x8100 + 0x0806": "arp.aw100",
    "0x9100 + 0x0806": "arp.ax91",
}

CELLS = 0
BAD = []


def cmp(what, got, want):
    global CELLS
    CELLS += 1
    if got != want:
        BAD.append("%s: doc=%r log=%r" % (what, got, want))


def cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def audit(text, rows_log):
    j = json.load(open(JSON))
    envs, facts = j["envs"], j["facts"]

    for line in text.split("\n"):
        if not line.startswith("|"):
            continue
        c = cells(line)
        if not c or c[0] not in ALIAS:
            continue
        env = ALIAS[c[0]]
        m = None
        for x in c[1:]:
            m = re.search(r"\*\*(\d+)/(\d+)\*\*", x)
            if m:
                break
        if not m:
            continue
        cmp("%s.live" % env, int(m.group(1)), envs[env]["live"])
        cmp("%s.of" % env, int(m.group(2)), envs[env]["cells"])
        if re.match(r"^[gx]\d+_\d+", c[-1]):
            cmp("%s.dead" % env,
                sorted(x.strip() for x in c[-1].split(",")),
                sorted(envs[env]["dead_set"]))

    # the eight tag-sensitive cells: plain column and tagged column
    for line in text.split("\n"):
        if not line.startswith("|"):
            continue
        c = cells(line)
        if not c or not re.match(r"^\(\d+,\d+\)$", c[0]):
            continue
        off, ln = [int(x) for x in c[0].strip("()").split(",")]
        arm = "g%d_%d" % (off, ln)
        for col, env in ((1, "recv.p"), (2, "recv.w100")):
            alive = c[col].replace("*", "").strip() == "жив"
            cmp("cell.%s.%s" % (arm, env), alive, arm in envs[env]["live_set"])

    # the policy-drop table
    for line in text.split("\n"):
        if not line.startswith("|"):
            continue
        c = cells(line)
        if len(c) != 3 or not c[0].startswith("`"):
            continue
        if c[0].startswith("`@ll,16,2`"):
            pair = ("p16_2", "w16_2")
        elif c[0].startswith("`@ll,14,2`"):
            pair = ("p14_2", "w14_2")
        else:
            continue
        for col, arm in ((1, pair[0]), (2, pair[1])):
            cmp("drop.%s.delivered" % arm, "доставлен" in c[col],
                int(rows_log[arm]["live"]) > 0)
    for line in text.split("\n"):
        c = cells(line) if line.startswith("|") else []
        if len(c) == 3 and c[0].startswith("| без записи"):
            pass
    for line in text.split("\n"):
        c = cells(line) if line.startswith("|") else []
        if len(c) == 3 and c[0].startswith("без записи"):
            for col, arm in ((1, "ctl_p"), (2, "ctl_w")):
                cmp("drop.%s.delivered" % arm, "доставлен" in c[col],
                    int(rows_log[arm]["live"]) > 0)

    # §6: the three wire changes of one and the same cell
    for line in text.split("\n"):
        if not line.startswith("|"):
            continue
        c = cells(line)
        if len(c) != 3 or c[0] not in ("голый", "0x8100", "0x9100"):
            continue
        m = re.match(r"^`([0-9a-f:>]+)`$", c[1])
        if not m:
            continue
        env = {"голый": "ndin.p", "0x8100": "ndin.w100",
               "0x9100": "ndin.x91"}[c[0]]
        cmp("wire.%s" % env, m.group(1), facts["ndin_g8_1"][env]["wchg"])

    # §8: where the sixteen bytes landed
    for line in text.split("\n"):
        if not line.startswith("|"):
            continue
        c = cells(line)
        if len(c) != 4 or not re.match(r"^\d+\.\.\d+$", c[1]):
            continue
        env = {"голый": "arp.a", "0x8100": "arp.aw100"}.get(c[0])
        if not env:
            continue
        f = facts["arp_x20_16"][env]
        cmp("span.%s" % env, c[1], "%d..%d" % (f["first"], f["last"]))
        cmp("span.%s.msg" % env, c[2], "%d..%d" % (14 + 0 if env == "arp.a"
                                                   else 18, f["msg_last"]))
        m = re.search(r"\*\*(\d+) байт", c[3])
        cmp("span.%s.past" % env, int(m.group(1)) if m else None, f["past"])

    g = facts["ndin_g8_1"]
    cmp("ttl.plain", g["ndin.p"]["wchg"], "22:40>90")
    cmp("ttl.tagged", g["ndin.w100"]["wchg"], "26:40>90")
    cmp("ttl.9100", g["ndin.x91"]["wchg"], "22:12>90")
    cmp("far.identical", facts["recv_far_identical_p_w100"], True)
    cmp("x91.wire.len", facts["recv_x91_wire_len"], 64)
    cmp("x91.wire.12_16", facts["recv_x91_wire_12_16"], "91000064")
    cmp("x91.far.12_16", facts["recv_x91_ctrl_rhex_12_16"], "91000064")
    cmp("probe.m100", facts["probe_m100_ctl_wire_equals_plain"], True)
    cmp("tagstore.rc", facts["tagstore"][0]["rc"], "0")
    cmp("tagstore.acks", facts["tagstore"][0]["acks"], "1")
    for env, first, last, past in (("arp.a", 34, 49, 8),
                                   ("arp.aw100", 38, 53, 8)):
        f = facts["arp_x20_16"][env]
        cmp("%s.first" % env, f["first"], first)
        cmp("%s.last" % env, f["last"], last)
        cmp("%s.past" % env, f["past"], past)

    # the numbers block
    derived = {"arms": j["arms"],
               "f560.lines": sum(1 for l in open(LOG, "rb")
                                 if l.startswith(b"F560"))}
    for env, e in envs.items():
        derived[env + ".live"] = e["live"]
    derived["recv_x91_wire_len"] = facts["recv_x91_wire_len"]
    derived["ttl.plain.index"] = int(g["ndin.p"]["wchg"].split(":")[0])
    derived["ttl.tagged.index"] = int(g["ndin.w100"]["wchg"].split(":")[0])
    derived["ttl.9100.index"] = int(g["ndin.x91"]["wchg"].split(":")[0])
    derived["ttl.9100.old"] = int(g["ndin.x91"]["wchg"].split(":")[1]
                                  .split(">")[0])
    for env, tag in (("arp.a", "plain"), ("arp.aw100", "vlan")):
        f = facts["arp_x20_16"][env]
        derived["arp.%s.first" % tag] = f["first"]
        derived["arp.%s.last" % tag] = f["last"]
        derived["arp.%s.past" % tag] = f["past"]
    inblock = False
    for line in text.split("\n"):
        if line.startswith("## 14."):
            inblock = True
            continue
        if inblock and line.startswith("## "):
            inblock = False
        if not inblock:
            continue
        m = re.match(r"^- ([a-z0-9_.]+) = (-?\d+)$", line)
        if not m:
            continue
        k, v = m.group(1), int(m.group(2))
        if k not in derived:
            global CELLS
            CELLS += 1
            BAD.append("num.%s: not derived from any log" % k)
            continue
        cmp("num.%s" % k, v, derived[k])


def drop_rows():
    rows = {}
    for raw in open(LOG, "rb"):
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line.startswith("F560 R|env=drop.drop|"):
            continue
        x = dict(kv.split("=", 1) for kv in line.split("|")[1:])
        rows[x["arm"]] = x
    return rows


def main():
    msgs = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = msgs[0] if msgs else DOC
    audit(open(path, encoding="utf-8").read(), drop_rows())
    print("audit_f38_doc: %d cells, %d discrepancies" % (CELLS, len(BAD)))
    for b in BAD[:20]:
        print("DIFF %s" % b)
    return 1 if BAD else 0


def selftest():
    """three single-cell substitutions in a copy, each must be noticed"""
    text = open(DOC, encoding="utf-8").read()
    subs = [("**23/36**", "**24/36**"),
            ("| `22:40>90` | ttl (14+8)", "| `23:40>90` | ttl (14+8)"),
            ("- ttl.tagged.index = 26", "- ttl.tagged.index = 22")]
    rc_all = 0
    for i, (old, new) in enumerate(subs):
        if old not in text:
            print("SELFTEST-BROKEN %d: %r not in the document" % (i, old))
            rc_all = 1
            continue
        tmp = "/tmp/f38_doc_sub%d.md" % i
        open(tmp, "w", encoding="utf-8").write(text.replace(old, new, 1))
        r = subprocess.run([sys.executable, __file__, tmp],
                           capture_output=True, text=True)
        n = len([l for l in r.stdout.split("\n") if l.startswith("DIFF")])
        ok = r.returncode != 0 and n >= 1
        print("SELFTEST %d %s (%d discrepancies)" % (i, "caught" if ok else
                                                      "SURVIVED", n))
        if not ok:
            rc_all = 1
    return rc_all


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(main())
