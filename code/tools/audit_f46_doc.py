#!/usr/bin/env python3
"""audit_f46_doc.py -- does SUMMARY.md say what the log says?

A separate pair of eyes: this script does NOT import the generator that printed
the tables (F40's lesson: a table checked by the code that printed it proves
nothing).  It finds the eight tables of the document by their header line,
parses the log itself, derives every cell again and compares.

Usage: audit_f46_doc.py [--doc SUMMARY.md] [--log logs/f46_rep1.log]
                        [--mutate ll|nh|toll|th|dst|repair|rd|ld]
"""
import argparse
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F46-egress-doors/SUMMARY.md")
LOG = os.path.join(ROOT, "logs/f46_rep1.log")
LL_CELLS = ["l0_2", "l0_6", "l2_4", "l4_2", "l6_2", "l8_6", "l10_2", "l11_1",
            "l12_2", "l13_1", "l12_4", "l14_2"]
NH_CELLS = ["n0_2s", "n0_2t", "n0_2x", "n0_1", "n1_1", "n2_2", "n4_2", "n6_2",
            "n8_1", "n8_1s", "n8_2p", "n8_2x", "n9_1", "n10_2", "n10_10",
            "n12_4", "n12_8", "n14_2", "n16_4", "n16_8", "n20_2"]
TH_CELLS = ["t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4", "t12_4", "t16_2"]
FAIL = []
N = 0


def ck(cond, what, detail=""):
    global N
    N += 1
    if not cond:
        FAIL.append(f"{what}{(' :: ' + detail) if detail else ''}")


def parse_log(path):
    arms = {}
    for line in open(path, errors="replace"):
        if not line.startswith("F568 A|"):
            continue
        d = {}
        for kv in line.strip().split("|")[1:]:
            if "=" in kv:
                k, v = kv.split("=", 1)
                d[k] = v
        arms[(d["sec"], d["door"], d["cls"], d["arm"])] = d
    return arms


def iv(d, k):
    try:
        return int(d.get(k, ""))
    except (TypeError, ValueError):
        return 0


def parse_tables(text):
    tables = {}
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].startswith("| дверь · класс |"):
            hdr = [c.strip() for c in lines[i].strip().strip("|").split("|")]
            j = i + 2
            rows = []
            while j < len(lines) and lines[j].startswith("|"):
                rows.append([c.strip() for c in lines[j].strip().strip("|").split("|")])
                j += 1
            tables[tuple(hdr)] = rows
            i = j
        else:
            i += 1
    return tables


def table(t, col):
    for hdr, rows in t.items():
        if col in hdr:
            return rows
    raise SystemExit("table with column %r not found" % col)


def pair(cell):
    m = re.match(r"`(\w+)`\s*·\s*(\w+)", cell)
    return (m.group(1), m.group(2)) if m else None


def cells_of(s):
    s = s.replace("*", "").replace("`", "")
    return [c.strip() for c in s.split(",") if c.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--doc", default=DOC)
    ap.add_argument("--log", default=LOG)
    ap.add_argument("--mutate", default="")
    args = ap.parse_args()

    text = open(args.doc, errors="replace").read()
    if args.mutate:
        subs = {"ll": ("| `out` · loc | **0/12** |", "| `out` · loc | **1/12** |"),
                "nh": ("| `out` · loc | **12/21** |", "| `out` · loc | **13/21** |"),
                "toll": ("| `lin` · in | 1 | InHdrErrors 0, InDelivers 1 | да |",
                         "| `lin` · in | 1 | InHdrErrors 1, InDelivers 1 | да |"),
                "th": ("| `post` · fwd | **0/8** | 8 |", "| `post` · fwd | **8/8** | 0 |"),
                "dst": ("| `fwd` · fwd | 1 | нет |", "| `fwd` · fwd | 0 | да |"),
                "repair": ("| `post` · fwd | r_ttl10 | 10 | 1 | InHdrErrors 0 | да |",
                           "| `post` · fwd | r_ttl10 | 10 | 1 | InHdrErrors 1 | нет |"),
                "rd": ("| `out` · loc | 1 | 1 | 0 | 1 | 1 | 1 |",
                       "| `out` · loc | 1 | 1 | 1 | 1 | 1 | 1 |"),
                "ld": ("| `lin` · in | жив 1, доставлено 1, UdpInErrors 0 |",
                       "| `lin` · in | жив 0, доставлено 1, UdpInErrors 0 |")}
        if args.mutate not in subs:
            raise SystemExit("unknown mutation " + args.mutate)
        a, b = subs[args.mutate]
        if a not in text:
            raise SystemExit("target not found: " + a)
        text = text.replace(a, b, 1)
        print(f"mutated {args.mutate}")

    arms = parse_log(args.log)
    t = parse_tables(text)
    ck(len(t) == 8, "the document has the eight tables", str(len(t)))

    # ---- 2. @ll ----
    rows = table(t, "живых из 12")
    for cells in rows:
        p = pair(cells[0])
        live = [c for c in LL_CELLS
                if iv(arms.get(("ll", p[0], p[1], c), {}), "lives") == 1]
        wire = 0
        for c in live:
            r = arms[("ll", p[0], p[1], c)]
            h = r.get("rhex", "-")
            imm = r.get("imm", "")
            off, ln = iv(r, "off"), iv(r, "len")
            if h != "-" and len(imm) == 2 * ln and h[2 * off:2 * off + 2 * ln] == imm:
                wire += 1
        ck(cells[1].replace("*", "") == f"{len(live)}/12", f"§2 {p}: live",
           f"doc {cells[1]} log {len(live)}/12")
        ck(cells_of(cells[2]) == [c for c in LL_CELLS if c not in live],
           f"§2 {p}: refused list", f"doc {cells[2]}")
        ck(cells[3] == str(wire), f"§2 {p}: cells on the wire", f"doc {cells[3]} log {wire}")

    # ---- 3. @nh ----
    rows = table(t, "живых из 21")
    for cells in rows:
        p = pair(cells[0])
        live = [c for c in NH_CELLS
                if iv(arms.get(("nh", p[0], p[1], c), {}), "lives") == 1]
        ck(cells[1].replace("*", "") == f"{len(live)}/21", f"§3 {p}: live",
           f"doc {cells[1]} log {len(live)}/21")
        ck(cells_of(cells[2]) == [c for c in NH_CELLS if c not in live],
           f"§3 {p}: refused list")

    # ---- 4. the toll ----
    rows = table(t, "у получателя") if False else table(t, "доставлено")
    for cells in rows:
        p = pair(cells[0])
        if len(cells) != 4:
            continue
        r = arms.get(("cs", p[0], p[1], "r_ttl0"), {})
        hdrn = iv(r, "phdr") if p[1] == "in" else iv(r, "rihdr")
        deln = iv(r, "pdeliv") if p[1] == "in" else iv(r, "ideliv")
        done = iv(r, "precv") if p[1] == "in" else iv(r, "udpn")
        ck(cells[1] == str(iv(r, "lives")), f"§4 {p}: accepted")
        ck(cells[2] == f"InHdrErrors {hdrn}, InDelivers {deln}",
           f"§4 {p}: counters", f"doc {cells[2]}")
        ck(cells[3] == ("да" if done else "нет"), f"§4 {p}: delivered")

    # ---- 5. the repair ----
    rows = table(t, "клетка")
    for cells in rows:
        p = pair(cells[0])
        r = arms.get(("cs", p[0], p[1], cells[1]))
        ck(r is not None, f"§5 {p} {cells[1]}: the arm exists")
        if r is None:
            continue
        ck(cells[2] == str(iv(r, "cso")), f"§5 {p} {cells[1]}: csum_offset")
        ck(cells[3] == str(iv(r, "lives")), f"§5 {p} {cells[1]}: accepted")
        done = iv(r, "precv") if p[1] == "in" else iv(r, "udpn")
        ck(cells[5] == ("да" if done else "нет"), f"§5 {p} {cells[1]}: delivered",
           f"doc {cells[5]}")
        if p[1] == "in":
            want = f"InHdrErrors {iv(r,'phdr')}, UdpInErrors {iv(r,'puerr')}"
        else:
            want = f"InHdrErrors {iv(r,'rihdr')}"
        ck(cells[4] == want, f"§5 {p} {cells[1]}: the receiver", f"doc {cells[4]} != {want}")

    # ---- 6. the transport ----
    rows = table(t, "доставлено из 8")
    for cells in rows:
        p = pair(cells[0])
        ok = err = 0
        for c in TH_CELLS:
            r = arms.get(("th", p[0], p[1], c))
            if r is None:
                continue
            ok += 1 if (iv(r, "precv") if p[1] == "in" else iv(r, "udpn")) else 0
            err += 1 if (iv(r, "puerr") if p[1] == "in" else iv(r, "rudperr")) else 0
        ck(cells[1].replace("*", "") == f"{ok}/8", f"§6 {p}: delivered",
           f"doc {cells[1]} log {ok}/8")
        ck(cells[2] == str(err), f"§6 {p}: UdpInErrors", f"doc {cells[2]} log {err}")

    # ---- 7. destination ----
    rows = table(t, "кадр на проводе")
    for cells in rows:
        p = pair(cells[0])
        r = arms.get(("nh", p[0], p[1], "n16_4"), {})
        ck(cells[1] == str(iv(r, "lives")), f"§7 {p}: accepted")
        if p[1] == "in":
            want = (f"InDelivers {iv(r,'pdeliv')}, InNoRoutes {iv(r,'pnr')}, "
                    f"доставлено {iv(r,'precv')}")
        else:
            want = (f"кадров {iv(r,'tapn')}, InHdrErrors {iv(r,'rihdr')}, "
                    f"InDelivers {iv(r,'rideliv')}")
            ck(cells[2] == ("нет" if iv(r, "tapn") == 0 else "да"),
               f"§7 {p}: frame on the wire", f"doc {cells[2]}")
        ck(cells[3] == want, f"§7 {p}: the receiver", f"doc {cells[3]} != {want}")

    # ---- 8. reads ----
    rows = table(t, "q_ttl")
    for cells in rows:
        p = pair(cells[0])
        for i, arm in enumerate(("q_ttl", "q_ver", "q_ttl_x", "q_src", "q_dst", "q_sport")):
            r = arms.get(("rd", p[0], p[1], arm))
            if r is None:
                continue
            ck(cells[1 + i] == str(iv(r, "lives")), f"§8 {p} {arm}",
               f"doc {cells[1+i]} log {iv(r,'lives')}")

    # ---- 9. the invisible write ----
    rows = table(t, "d_ttl")
    for cells in rows:
        p = pair(cells[0])
        for i, arm in enumerate(("d_ttl", "d_src", "d_port", "d_ll")):
            r = arms.get(("ld", p[0], p[1], arm))
            if r is None:
                continue
            want = (f"жив {iv(r,'lives')}, доставлено {iv(r,'precv')}, "
                    f"UdpInErrors {iv(r,'puerr')}")
            ck(cells[1 + i] == want, f"§9 {p} {arm}", f"doc {cells[1+i]} != {want}")

    print(f"AUDIT_F46 checks={N} failures={len(FAIL)}")
    for f in FAIL[:30]:
        print("  FAIL", f)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
