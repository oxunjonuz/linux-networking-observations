#!/usr/bin/env python3
"""f568_summary.py -- derive every table of F46 from the log, not from memory.

Usage: f568_summary.py [log] [--json out.json]
Prints markdown tables; audit_f46_doc.py re-derives the same numbers from the
same log and compares them with what is written in SUMMARY.md.
"""
import json
import sys
import os

ROOT = "/work/kernel-sec"
LL, NH, TH = 0, 1, 2
IPO, UDPO = 14, 34


def rows(path):
    out = []
    for line in open(path, errors="replace"):
        if not line.startswith("F568 A|"):
            continue
        d = {}
        for kv in line.strip().split("|")[1:]:
            if "=" in kv:
                k, v = kv.split("=", 1)
                d[k] = v
        out.append(d)
    return out


def n(d, k):
    try:
        return int(d.get(k, ""))
    except ValueError:
        try:
            return int(float(d.get(k, "")))
        except ValueError:
            return 0


def main():
    log = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") \
        else os.path.join(ROOT, "logs/f46_rep1.log")
    R = rows(log)
    idx = {}
    for r in R:
        idx.setdefault((r["sec"], r["door"], r["cls"], r["arm"]), r)
    pairs = []
    for r in R:
        p = (r["door"], r["cls"])
        if p not in pairs:
            pairs.append(p)

    # reference + noise per pair
    ref = {}
    for p in pairs:
        c1 = idx.get(("ctl", p[0], p[1], "ctl"))
        c2 = idx.get(("ctl", p[0], p[1], "ctl2"))
        ref[p] = (c1, c2)

    out = {"log": os.path.basename(log), "tables": {}}

    # ---------------- LL ----------------
    cells = ["l0_2", "l0_6", "l2_4", "l4_2", "l6_2", "l8_6", "l10_2", "l11_1",
             "l12_2", "l13_1", "l12_4", "l14_2"]
    ll = []
    for p in pairs:
        live = [c for c in cells if n(idx[("ll", p[0], p[1], c)], "lives") == 1]
        wire = []
        for c in live:
            r = idx[("ll", p[0], p[1], c)]
            h = r.get("rhex", "-")
            off = n(r, "off")
            ln = n(r, "len")
            imm = r.get("imm", "")
            if h == "-" or len(imm) != 2 * ln:
                continue
            if h[2 * off:2 * off + 2 * ln] == imm:
                wire.append(c)
        ll.append({"door": p[0], "cls": p[1], "live": len(live),
                   "cells": live, "on_the_wire": len(wire)})
    out["tables"]["ll"] = ll

    # ---------------- NH ----------------
    ncells = ["n0_2s", "n0_2t", "n0_2x", "n0_1", "n1_1", "n2_2", "n4_2", "n6_2",
              "n8_1", "n8_1s", "n8_2p", "n8_2x", "n9_1", "n10_2", "n10_10",
              "n12_4", "n12_8", "n14_2", "n16_4", "n16_8", "n20_2"]
    nh = []
    for p in pairs:
        if ("nh", p[0], p[1], "n0_2s") not in idx:
            continue
        live = [c for c in ncells if n(idx[("nh", p[0], p[1], c)], "lives") == 1]
        nh.append({"door": p[0], "cls": p[1], "live": len(live), "cells": live})
    out["tables"]["nh"] = nh

    # ---------------- the toll (a ttl write) ----------------
    toll = []
    for p in pairs:
        r = idx.get(("cs", p[0], p[1], "r_ttl0"))
        if not r:
            continue
        toll.append({"door": p[0], "cls": p[1],
                     "lives": n(r, "lives"),
                     "ihdr": n(r, "rihdr"), "ideliv": n(r, "rideliv"),
                     "udpn": n(r, "udpn"),
                     "phdr": n(r, "phdr"), "pdeliv": n(r, "pdeliv"),
                     "precv": n(r, "precv")})
    out["tables"]["toll"] = toll

    # ---------------- the repair ----------------
    rep = []
    for p in pairs:
        if ("cs", p[0], p[1], "r_ttl10") not in idx:
            continue
        for arm in ("r_ttl0", "r_ttl12", "r_ttl6", "r_ttl10", "r_tos0",
                    "r_tos10", "r_src0", "r_src10", "r_chk10"):
            r = idx.get(("cs", p[0], p[1], arm))
            if not r:
                continue
            rep.append({"door": p[0], "cls": p[1], "arm": arm,
                        "cso": n(r, "cso"), "lives": n(r, "lives"),
                        "rchg": n(r, "rchg"),
                        "ihdr": n(r, "rihdr"), "udpn": n(r, "udpn"),
                        "phdr": n(r, "phdr"), "puerr": n(r, "puerr"),
                        "precv": n(r, "precv"), "rhex": r.get("rhex", "-")})
    out["tables"]["repair"] = rep

    # ---------------- the transport toll ----------------
    tcells = ["t0_2", "t2_2", "t4_2", "t6_2", "t8_2", "t0_4", "t12_4", "t16_2"]
    th = []
    for p in pairs:
        if ("th", p[0], p[1], "t0_2") not in idx:
            continue
        d = {"door": p[0], "cls": p[1], "delivered": 0, "udperr": 0, "lines": []}
        for c in tcells:
            r = idx[("th", p[0], p[1], c)]
            if p[1] == "in":
                ok = n(r, "precv")
                err = n(r, "puerr")
            else:
                ok = n(r, "udpn")
                err = n(r, "rudperr")
            d["delivered"] += 1 if ok else 0
            d["udperr"] += 1 if err else 0
            d["lines"].append({"arm": c, "ok": ok, "err": err,
                               "usport": n(r, "usport"), "prsport": n(r, "prsport")})
        th.append(d)
    out["tables"]["th"] = th

    # ---------------- the destination write, five doors ----------------
    dst = []
    for p in pairs:
        r = idx.get(("nh", p[0], p[1], "n16_4"))
        if not r:
            continue
        dst.append({"door": p[0], "cls": p[1], "lives": n(r, "lives"),
                    "tapn": n(r, "tapn"), "ihdr": n(r, "rihdr"),
                    "ideliv": n(r, "rideliv"), "phdr": n(r, "phdr"),
                    "pdeliv": n(r, "pdeliv"), "pnr": n(r, "pnr"),
                    "precv": n(r, "precv")})
    out["tables"]["dst"] = dst

    # ---------------- reads at the egress door ----------------
    rd = []
    for p in pairs:
        for arm in ("q_ttl", "q_ver", "q_ttl_x", "q_src", "q_dst", "q_sport"):
            r = idx.get(("rd", p[0], p[1], arm))
            if r:
                rd.append({"door": p[0], "cls": p[1], "arm": arm,
                           "lives": n(r, "lives")})
    out["tables"]["rd"] = rd

    # ---------------- did the invisible write land? ----------------
    ld = []
    for p in pairs:
        for arm in ("d_ttl", "d_src", "d_port", "d_ll"):
            r = idx.get(("ld", p[0], p[1], arm))
            if r:
                ld.append({"door": p[0], "cls": p[1], "arm": arm,
                           "lives": n(r, "lives"), "precv": n(r, "precv"),
                           "puerr": n(r, "puerr")})
    out["tables"]["ld"] = ld

    # ---------------- markdown ----------------
    md = []
    md.append("### 2. `@ll`: где заголовок MAC есть, а где его нет\n")
    md.append("| дверь · класс | живых из 12 | отказаны | видно на проводе |")
    md.append("|---|---|---|---|")
    for d in ll:
        dead = [c for c in cells if c not in d["cells"]]
        md.append(f"| `{d['door']}` · {d['cls']} | **{d['live']}/12** | "
                  f"{', '.join(dead) if dead else '—'} | {d['on_the_wire']} |")
    md.append("")
    md.append("### 3. `@nh`: один белый список на шести дверях\n")
    md.append("| дверь · класс | живых из 21 | отказаны |")
    md.append("|---|---|---|")
    for d in nh:
        dead = [c for c in ncells if c not in d["cells"]]
        md.append(f"| `{d['door']}` · {d['cls']} | **{d['live']}/21** | "
                  f"{', '.join(dead)} |")
    md.append("")
    md.append("### 4. Запись ttl: кто платит\n")
    md.append("| дверь · класс | принято | у получателя | доставлено |")
    md.append("|---|---|---|---|")
    for d in toll:
        if d["cls"] == "in":
            got = f"InHdrErrors {d['phdr']}, InDelivers {d['pdeliv']}"
            dl = "да" if d["precv"] else "нет"
        else:
            got = f"InHdrErrors {d['ihdr']}, InDelivers {d['ideliv']}"
            dl = "да" if d["udpn"] else "нет"
        md.append(f"| `{d['door']}` · {d['cls']} | {d['lives']} | {got} | {dl} |")
    md.append("")
    md.append("### 5. Пересчёт: одно и то же значение, четыре `csum_offset`\n")
    md.append("| дверь · класс | клетка | cso | принято | у получателя | доставлено |")
    md.append("|---|---|---|---|---|---|")
    for d in rep:
        got = ("InHdrErrors %d, UdpInErrors %d" % (d['phdr'], d['puerr'])) if d['cls'] == "in" \
            else ("InHdrErrors %d" % d['ihdr'])
        dl = ("да" if d["precv"] else "нет") if d["cls"] == "in" else ("да" if d["udpn"] else "нет")
        md.append(f"| `{d['door']}` · {d['cls']} | {d['arm']} | {d['cso']} | "
                  f"{d['lives']} | {got} | {dl} |")
    md.append("")
    md.append("### 6. Транспорт: восемь клеток, две цены\n")
    md.append("| дверь · класс | доставлено из 8 | UdpInErrors |")
    md.append("|---|---|---|")
    for d in th:
        md.append(f"| `{d['door']}` · {d['cls']} | **{d['delivered']}/8** | {d['udperr']} |")
    md.append("")
    md.append("### 7. Запись в адрес назначения: пять дверей\n")
    md.append("| дверь · класс | принято | кадр на проводе | у получателя |")
    md.append("|---|---|---|---|")
    for d in dst:
        if d["cls"] == "in":
            got = f"InDelivers {d['pdeliv']}, InNoRoutes {d['pnr']}, доставлено {d['precv']}"
        else:
            got = f"кадров {d['tapn']}, InHdrErrors {d['ihdr']}, InDelivers {d['ideliv']}"
        wire = "—" if d['cls'] == "in" else ("нет" if d['tapn'] == 0 else "да")
        md.append(f"| `{d['door']}` · {d['cls']} | {d['lives']} | {wire} | {got} |")
    md.append("")
    md.append("### 8. Чтение на выходной двери\n")
    md.append("| дверь · класс | " + " | ".join(a for a in
                                                 ("q_ttl", "q_ver", "q_ttl_x", "q_src", "q_dst", "q_sport")) + " |")
    md.append("|---|---|---|---|---|---|---|")
    for d in rd:
        pass
    seen = {}
    for d in rd:
        seen.setdefault((d["door"], d["cls"]), {})[d["arm"]] = d["lives"]
    for k, v in seen.items():
        md.append(f"| `{k[0]}` · {k[1]} | " +
                  " | ".join(str(v.get(a, "-")) for a in
                             ("q_ttl", "q_ver", "q_ttl_x", "q_src", "q_dst", "q_sport")) + " |")
    md.append("")
    md.append("### 9. Запись, которую не видит никто: легла ли она\n")
    md.append("| дверь · класс | " + " | ".join(("d_ttl", "d_src", "d_port", "d_ll")) + " |")
    md.append("|---|---|---|---|---|")
    seen2 = {}
    for d in ld:
        seen2.setdefault((d["door"], d["cls"]), {})[d["arm"]] = d
    for k, v in seen2.items():
        md.append(f"| `{k[0]}` · {k[1]} | " + " | ".join(
            (f"жив {v[a]['lives']}, доставлено {v[a]['precv']}, UdpInErrors {v[a]['puerr']}"
             if a in v else "-") for a in ("d_ttl", "d_src", "d_port", "d_ll")) + " |")
    text = "\n".join(md)
    out["markdown"] = text

    if "--json" in sys.argv:
        p = sys.argv[sys.argv.index("--json") + 1]
        json.dump(out, open(p, "w"), indent=1)
        print(f"JSON {p}")
    print(text)


if __name__ == "__main__":
    main()
