#!/usr/bin/env python3
"""f569_summary.py -- derive every table of F47 from the frozen logs.

Nothing here is typed by hand: each table is built from the F569 lines of the
two boots, and `audit_f47_doc.py` re-derives the same tables and compares them
with the document, so a table that drifts from the log turns the audit red.

usage: f569_summary.py [--json out.json] [--md]
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOGS = [ROOT / "logs/f47_rep1.log", ROOT / "logs/f47_rep2.log"]

CELLS = ["hop90", "hop00", "hop01", "hop64", "flow2", "tc4", "ver9", "saddr",
         "saddr_same", "daddr", "plen2", "nh1"]
READS = ["rd_hop64", "rd_hop00", "rd_src", "rd_dst"]
PAIRS = [("out", "loc"), ("post", "loc"), ("egr", "loc"),
         ("post", "fwd"), ("fwd", "fwd"), ("egr", "fwd"), ("pre", "fwd")]
DOORS = ["out", "post", "fwd", "pre", "egr"]


def fields(line):
    d = {}
    for kv in line.split("|")[1:]:
        if "=" in kv:
            k, v = kv.split("=", 1)
            d[k] = v
    return d


def load():
    arms, iso, order = {}, {}, []
    for lg in LOGS:
        boot = lg.name.split("_")[-1].split(".")[0]
        for ln in lg.read_text(errors="replace").splitlines():
            if ln.startswith("F569 A|"):
                f = fields(ln)
                key = (boot, f["door"], f["cls"], f["arm"])
                arms[key] = f
                if boot == "rep1":
                    order.append(key)
            elif ln.startswith("F569 ISO|"):
                f = fields(ln)
                iso.setdefault((boot, f["arm"]), []).append(f)
    add_deltas(arms, order)
    add_deltas(arms, [k for k in arms if k[0] == "rep2"])
    return arms, iso


CUM_KEYS = ["i6hdr", "i6addr", "i6unk", "i6trunc", "i6noroute", "i6deliv",
            "u6in", "u6err", "u6noport"]


def add_deltas(arms, order):
    """The instrument prints cumulative receiver counters; the verdict of an
    arm is the difference from the previous arm, in the order they were run."""
    prev = {}
    for n, key in enumerate(order):
        f = arms[key]
        if n == 0:
            f["_first"] = "1"
            for c in CUM_KEYS:
                f["d_" + c] = "NA"
        for c in CUM_KEYS:
            cur = int(f.get(c, "0") or 0)
            f["d_" + c] = str(cur - prev.get(c, cur))
            prev[c] = cur


def both(arms, door, cls, arm, key):
    a = arms.get(("rep1", door, cls, arm), {}).get(key)
    b = arms.get(("rep2", door, cls, arm), {}).get(key)
    return a if a == b else "%s/%s" % (a, b)


def i(f, k, d="-1"):
    try:
        return int(f.get(k, d))
    except (TypeError, ValueError):
        return -1


def tables(arms, iso):
    out = {}

    # 1. the guard: cells accepted per door and class (lives > 0)
    g = []
    for cell in CELLS:
        row = []
        for d, c in PAIRS:
            f = arms.get(("rep1", d, c, cell), {})
            row.append("yes" if i(f, "lives") > 0 else "no")
        g.append([cell] + row)
    out["guard"] = {
        "head": ["cell (store)"] + ["%s/%s" % (d, c) for d, c in PAIRS],
        "rows": g,
    }

    # 2. the fate at the receiver, per cell and door
    f = []
    for cell in CELLS + READS:
        row = []
        for d, c in PAIRS:
            a = arms.get(("rep1", d, c, cell), {})
            if a.get("_first") == "1" or a.get("u6in_d") == "NA":
                row.append("n/a")
                continue
            if not a:
                row.append("-")
                continue
            if i(a, "u6in_d") > 0:
                row.append("delivered")
            elif i(a, "d_u6err") > 0:
                row.append("Udp6InErr")
            elif i(a, "d_i6addr") > 0:
                row.append("AddrErr")
            elif i(a, "tapn") == 0:
                row.append("no frame")
            else:
                row.append("?")
        f.append([cell] + row)
    out["fate"] = {
        "head": ["cell"] + ["%s/%s" % (d, c) for d, c in PAIRS],
        "rows": f,
    }

    # 3. hop limit on the wire and at the receiver, per door
    h = []
    for d, c in PAIRS:
        for cell in ("hop64", "hop90", "hop00", "hop01"):
            a = arms.get(("rep1", d, c, cell), {})
            tap = a.get("tap", "-")
            hop = "-"
            if tap not in ("-", "") and len(tap) >= 44:
                hop = tap[42:44]
            h.append(["%s/%s" % (d, c), cell, a.get("lives", "-"), hop,
                      a.get("u6in_d", "-"), a.get("i6deliv", "-")])
    out["hop"] = {"head": ["door", "cell", "lives", "hop on the wire",
                           "u6in_d", "i6deliv"], "rows": h}

    # 4. the counters of the refused cells and of the read side
    r = []
    for cell in ("ver9", "plen2", "nh1") + tuple(READS):
        row = [cell]
        for d, c in PAIRS:
            a = arms.get(("rep1", d, c, cell), {})
            row.append(a.get("lives", "-"))
        r.append(row)
    out["refused"] = {"head": ["cell (read / refused)"] +
                      ["%s/%s" % (d, c) for d, c in PAIRS],
                      "rows": r}

    # 5. the daddr cell: how many packets each door counted
    dd = []
    for d, c in PAIRS:
        a = arms.get(("rep1", d, c, "daddr"), {})
        dd.append(["%s/%s" % (d, c), a.get("cntp", "-"), a.get("lives", "-"),
                   a.get("tapn", "-"), a.get("u6in_d", "-"),
                   a.get("d_i6addr", "-"), a.get("pout_d", "-")])
    out["daddr"] = {"head": ["door", "cntp", "lives", "tapn", "u6in_d",
                             "i6addr", "pout_d"], "rows": dd}

    # 6. the checksum of a locally generated datagram, from its own bytes
    cs = []
    for d, c, arm in (("out", "loc", "hop64"), ("post", "loc", "hop64"),
                      ("egr", "loc", "hop64")):
        a = arms.get(("rep1", d, c, arm), {})
        tap = a.get("tap", "-")
        if tap in ("-", "") or len(tap) < 160:
            continue
        b = bytes.fromhex(tap)[14:]      # skip the MAC header
        if b[0] >> 4 != 6 or len(b) < 40 + 26:
            continue
        plen = (b[4] << 8) | b[5]
        src, dst = b[8:24], b[24:40]
        udp = b[40:40 + plen]
        pseudo = src + dst + plen.to_bytes(4, "big") + b"\0\0\0" + bytes([17])
        acc = 0
        blob = pseudo + udp
        if len(blob) % 2:
            blob += b"\0"
        for k in range(0, len(blob), 2):
            acc += (blob[k] << 8) | blob[k + 1]
            acc = (acc & 0xFFFF) + (acc >> 16)
        cs.append(["%s/%s" % (d, c), "%02x%02x" % (udp[6], udp[7]),
                   "%04x" % acc, "valid" if acc == 0xFFFF else "invalid"])
    out["csum"] = {"head": ["door", "field", "sum of the datagram",
                            "verdict"], "rows": cs}

    # 7. the isolation
    iso_rows = []
    for arm in ("ctl4", "v6on", "v6plus", "guard", "v6off", "quiet"):
        a = iso.get(("rep1", arm), [{}])[0]
        types = []
        for k in range(i(a, "nmsg", "0")):
            m = a.get("m%d" % k, "")
            if len(m) < 16:
                continue
            b = bytes.fromhex(m)
            if b[0] >> 4 == 6:
                nh = b[6]
                if nh == 0 and len(b) > 48 and b[48 - 6] == 58:
                    types.append("v6/hbh+icmp6")
                elif nh == 58:
                    types.append("v6/icmp6-%d" % b[40])
                else:
                    types.append("v6/nh%d" % nh)
            elif b[0] >> 4 == 4:
                types.append("v4/proto%d" % b[9])
            else:
                types.append("?")
        iso_rows.append([arm, a.get("send4", "-"), a.get("cnt", "-"),
                         a.get("gcnt", "-"), str(len(types)),
                         ",".join(types) or "-"])
    out["iso"] = {"head": ["arm", "send4", "cnt", "gcnt", "nmsg", "what"],
                  "rows": iso_rows}
    return out


def main(argv):
    arms, iso = load()
    t = tables(arms, iso)
    if "--json" in argv:
        p = Path(argv[argv.index("--json") + 1])
        p.write_text(json.dumps({"turn": 569, "finding": "F47",
                                 "kernel": "7.3.4-T563",
                                 "arms_per_boot": len([k for k in arms if k[0] == "rep1"]),
                                 "boots": len(LOGS),
                                 "tables": t}, indent=1) + "\n")
        print("wrote %s" % p)
    if "--md" in argv or "--json" not in argv:
        for name, tab in t.items():
            print("\n### %s\n" % name)
            head = tab["head"]
            print("| " + " | ".join(head) + " |")
            print("|" + "|".join(["---"] * len(head)) + "|")
            for row in tab["rows"]:
                print("| " + " | ".join(str(x) for x in row) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
