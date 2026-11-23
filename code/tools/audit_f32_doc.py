#!/usr/bin/env python3
"""audit_f32_doc.py -- recompute every cell of F32's tables from the boot logs.

The document is not allowed to say a number the logs do not say.  Each table row
is found in findings/F32-arp-family-guard/SUMMARY.md by its leftmost cell, the
remaining cells are re-derived from logs/f32_A_rep1.log (or the bare logs) and
compared one by one.

usage: python3 tools/audit_f32_doc.py [--quiet]
"""
import os
import re
import sys

ROOT = "/work/kernel-sec"
DOC = os.path.join(ROOT, "findings/F32-arp-family-guard/SUMMARY.md")
LOGS = ["logs/f32_A_rep1.log", "logs/f32_A_rep2.log", "logs/f32_M_rep1.log",
        "logs/f32_B_bare.log", "logs/f32_Q_bare.log"]

CELLS = []
MISMATCH = []


def cell(where, want, got):
    CELLS.append(1)
    if str(want).strip() != str(got).strip():
        MISMATCH.append("%s: doc=%r log=%r" % (where, want, got))


def arows(path):
    d = {}
    for ln in open(os.path.join(ROOT, path), errors="replace"):
        if ln.startswith("F555 A|"):
            f = ln.strip().split("|")
            d[f[1]] = dict(x.split("=", 1) for x in f[2:] if "=" in x)
    return d


def grep1(path, pattern):
    out = []
    for ln in open(os.path.join(ROOT, path), errors="replace"):
        m = re.search(pattern, ln)
        if m:
            out.append(m.groups())
    return out


def doc_table(section_start, header_first_cell):
    """rows of the first table after `section_start` whose header starts with
    `header_first_cell`; returns list of list-of-cells"""
    txt = open(DOC, errors="replace").read()
    i = txt.index(section_start)
    lines = txt[i:].splitlines()
    rows = []
    started = False
    for ln in lines:
        if not ln.startswith("|"):
            if started and rows:
                break
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if not started:
            if cells[0].startswith(header_first_cell):
                started = True
            continue
        if set(cells[0]) <= set("-: "):
            continue
        rows.append(cells)
    return rows


def main():
    global DOC
    quiet = "--quiet" in sys.argv
    if "--doc" in sys.argv:
        DOC = sys.argv[sys.argv.index("--doc") + 1]
    a = arows("logs/f32_A_rep1.log")
    m = arows("logs/f32_M_rep1.log")

    # ---- 2. family presence -------------------------------------------------
    fam = {}
    for tag, path in (("A553", "logs/f32_A_rep1.log"), ("AM553", "logs/f32_M_rep1.log"),
                      ("B19", "logs/f32_B_bare.log"), ("7.2.15", "logs/f32_Q_bare.log")):
        fam[tag] = {k: v for k, v in grep1(path, r"F555 FAM\|(\w+)\|(\d+)")}
    for row in doc_table("## 2. Семейство и хуки", "образ"):
        tag = re.match(r"`?([A-Za-z0-9._]+)", row[0]).group(1)
        for i, f in enumerate(["ip", "arp", "bridge", "netdev"], start=1):
            want = row[i].strip("*`")
            cell("§2 fam %s.%s" % (tag, f), want, fam[tag][f])
    for row in doc_table("## 2. Семейство и хуки", "хук"):
        hook = row[0].strip("`")
        rc = grep1("logs/f32_A_rep1.log", r"F555 HOOK\|%s\|(\d+)" % hook)[0][0]
        cell("§2 hook %s rc" % hook, row[1].strip("`*"), rc)
        origin = " ".join(row[2:])
        if hook == "forward":
            cell("§2 forward origin", "ядра", "ядра" if "ядра" in origin else origin)
        elif hook in ("prerouting", "postrouting", "ingress"):
            cell("§2 %s origin" % hook, "nft", "nft" if "nft" in origin else origin)

    # ---- 3. nine fields ----------------------------------------------------
    geom = {"htype": (0, 2, "0:2"), "ptype": (2, 2, "2:2"), "hlen": (4, 1, "4:1"),
            "plen": (5, 1, "5:1"), "operation": (6, 2, "6:2"),
            "saddr_ether": (8, 6, "8:6"), "saddr_ip": (14, 4, "14:4"),
            "daddr_ether": (18, 6, "18:6"), "daddr_ip": (24, 4, "24:4")}
    dbg = {}
    for g in grep1("logs/f32_A_rep1.log",
                   r"F555X c\.(\w+)\|\s*\[ payload write reg 1 => (\d+)b @ network header \+ (\d+)"):
        dbg[g[0]] = "%sb @ network header + %s" % (g[1], g[2])
    for row in doc_table("## 3. Девять полей", "поле"):
        w = row[0].replace("`", "").split()
        if len(w) > 2 and w[1] in ("saddr", "daddr"):
            name = w[1] + "_" + w[2]
        elif len(w) > 1 and w[0] == "arp":
            name = w[1]
        else:
            name = w[0]
        r = a["c." + name]
        cell("§3 %s geometry" % name, row[1].strip("`"), dbg.get(name))
        cell("§3 %s cnt" % name, row[2], r["cnt"])
        nfl = row[3]
        cell("§3 %s nflog" % name, "нет" if nfl.strip() == "нет" else nfl,
             "нет" if r["nfl"] == "0" else r["nfl"])
        chg = row[4]
        if chg.strip() == "—":
            cell("§3 %s bytes" % name, r["chg"], "-")
        else:
            m3 = re.match(r"(\d+) байт", chg.replace("*", "").strip())
            if m3:
                cell("§3 %s bytes_count" % name, m3.group(1),
                     len([x for x in r["chg"].split(",") if x]) if r["chg"] != "-" else 0)
            else:
                cell("§3 %s bytes" % name, chg.strip("*`").split()[0],
                     r["chg"].split(",")[0])
        verdict = row[5]
        cell("§3 %s verdict" % name, "мертво" in verdict, int(r["cnt"]) == 0)

    # ---- 4. the predicate as a function ------------------------------------
    txt = open(DOC, errors="replace").read()
    arms = {t: v for t, v in a.items() if re.match(r"^d\.\d+\.\d+$", t)}
    oarms = {t: v for t, v in a.items() if re.match(r"^e\.\d+\.\d+$", t)}
    alive_in = sum(1 for r in arms.values() if int(r["cnt"]) > 0)
    alive_out = sum(1 for r in oarms.values() if int(r["cnt"]) > 0)
    cell("§4 input alive", True, ("**%d из %d**" % (alive_in, len(arms))) in txt)
    cell("§4 output alive", True, ("**%d из %d**" % (alive_out, len(oarms))) in txt)

    # ---- 5. the @nh forms ---------------------------------------------------
    for row in doc_table("## 5. Дыра F31", "форма"):
        tag = row[0].strip("`")
        m2 = re.match(r"@nh,(\d+),(\d+)", tag)
        off, ln = int(m2.group(1)) // 8, int(m2.group(2)) // 8
        key = {(20, 16): "c2.spill2016", (28, 8): "c2.pad288", (7, 1): "c2.op71"}[(off, ln)]
        r = a[key]
        cell("§5 %s rc" % tag, row[1], r["rc"])
        cell("§5 %s cnt" % tag, row[2], r["cnt"])
        cell("§5 %s bytes" % tag, True,
             (row[3].strip().startswith("—") and r["chg"] == "-") or
             (row[3].strip().startswith("20…35") and r["chg"].startswith("20:")) or
             (row[3].strip().startswith("28…35") and r["chg"].startswith("28:")))

    # ---- 6. consequences ----------------------------------------------------
    f = {}
    for tag, cnt, rep in grep1("logs/f32_A_rep1.log",
                               r"F555 F\|(f\.\w+)\|rule=[^|]*\|rc=0\|cnt=(\d+)\|reply_i=(\d+)"):
        f[tag] = (cnt, rep)
    neigh = {}
    for tag, ip, fl in grep1("logs/f32_A_rep1.log", r"F555 ARP\|(f\.\w+)\|([0-9.]+)\|flags=(\S+)\|"):
        neigh[(tag, ip)] = fl
    rowmap = [("нет правила", "f.norule", "10.1.0.91", "10.5.5.5"),
              ("`arp saddr ip set 10.5.5.5`", "f.alive", "10.1.0.92", "10.5.5.5"),
              ("`arp htype set 2` (мертва)", "f.dead", "10.1.0.93", "10.5.5.6"),
              ("`arp operation set 2` (жива)", "f.op", "10.1.0.94", "10.5.5.7")]
    for row in doc_table("## 6. Что запись делает с хостом", "правило"):
        label = row[0]
        tag, spa, moved = next((t, s, mv) for lab, t, s, mv in rowmap
                               if lab == label or lab in label or label in lab)
        cell("§6 %s cnt" % tag, row[1], f[tag][0])
        cell("§6 %s reply" % tag, "есть" if row[2].strip("*").startswith("есть") else "нет",
             "есть" if f[tag][1] == "1" else "нет")
        cell("§6 %s neigh_spa" % tag, "нет" if row[3].strip("*") == "нет" else "есть",
             "нет" if neigh[(tag, spa)] == "none" else "есть")
        cell("§6 %s neigh_moved" % tag,
             "нет" if row[4].strip("*") == "нет" else "есть",
             "нет" if neigh[(tag, moved)] == "none" else "есть")
    cell("§6 multicast cells", True,
         len([t for t, r in arms.items() if r["cnt"] == "2"]) == 6 and "шесть клеток" in txt)

    # ---- 7. the receive-path prefilter ------------------------------------
    g = {}
    for tag, hlen, plen, flen, rx, cnt, nfl in grep1(
            "logs/f32_A_rep1.log",
            r"F555 G\|(g\.\w+)\|hlen=(\d+)\|plen=(\d+)\|flen=(\d+)\|rc=0\|rx_i0=(\d+)\|cnt=(\d+)\|nfl=(\d+)"):
        g[tag] = dict(hlen=hlen, plen=plen, flen=flen, rx=rx, cnt=cnt, nfl=nfl)
    for row in doc_table("## 7. Приёмный путь", "кадр"):
        tag = {"hlen=6 plen=4": "g.h6p4", "hlen=8 plen=16": "g.h8p16",
               "hlen=6 plen=8": "g.h6p8"}[row[0].strip("`")]
        r = g[tag]
        cell("§7 %s length" % tag, row[1], r["flen"])
        cell("§7 %s rx" % tag, "да" if row[2].strip("*") == "да" else "нет",
             "да" if r["rx"] == "1" else "нет")
        cell("§7 %s cnt" % tag, row[3].strip("`*"), r["cnt"])
        cell("§7 %s nflog" % tag, "нет" if row[4].strip("*") == "нет" else r["nfl"],
             "нет" if r["nfl"] == "0" else r["nfl"])

    if not quiet:
        for mline in MISMATCH:
            print("MISMATCH", mline)
    print("audit_f32_doc: %d cells, %d mismatches" % (len(CELLS), len(MISMATCH)))
    return 1 if MISMATCH else 0


if __name__ == "__main__":
    sys.exit(main())
